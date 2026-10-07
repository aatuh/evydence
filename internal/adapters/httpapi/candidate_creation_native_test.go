package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type candidateCreationHTTPFake struct {
	calls, guards int
	guardErr      error
	input         releaseapp.CreateReleaseCandidateInput
}

func (f *candidateCreationHTTPFake) AuthorizeCandidateCreation(context.Context, identitydomain.Actor, releaseapp.CreateReleaseCandidateInput) error {
	f.guards++
	return f.guardErr
}
func (f *candidateCreationHTTPFake) CreateReleaseCandidate(_ context.Context, a identitydomain.Actor, in releaseapp.CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error) {
	f.calls++
	f.input = in
	state, _ := releasedomain.ParseReleaseCandidateState("open")
	return releasedomain.ReleaseCandidate{ID: "candidate", TenantID: a.TenantID, ReleaseID: in.ReleaseID, Name: in.Name, State: state, Revision: 1, SchemaVersion: releasedomain.ReleaseCandidateSchemaVersion}, nil
}

func TestCandidateCreationRequiresNativeReplayAndCurrentGuard(t *testing.T) {
	base, secret := testServer(t)
	f := &candidateCreationHTTPFake{}
	if s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{CandidateCommands: f}); err == nil || s != nil {
		t.Error("focused candidate creation accepted aggregate replay")
	}
	s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{CandidateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	body := `{"release_id":"release","name":"Candidate","build_ids":[" b ","a","b"]}`
	one := postRaw(t, s, secret, "/v1/release-candidates", "current", []byte(body), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/release-candidates", "current", []byte(body), 201))
	f.guardErr = application.ErrForbidden
	postRaw(t, s, secret, "/v1/release-candidates", "current", []byte(body), 403)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("candidate replay skipped current authority", f)
	}
}

func TestCandidateCreationStrictPreflightRunsBeforeCommands(t *testing.T) {
	base, secret := testServer(t)
	f := &candidateCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{CandidateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	bad := []string{`{`, `[]`, `null`, `{}`, `{"release_id":"release","name":"Candidate"}{}`, `{"release_id":"release","name":"Candidate","name":"Other"}`, `{"release_id":"release","name":null}`, `{"Release_ID":"release","name":"Candidate"}`, `{"release_id":"release","name":"bad\u0000name"}`, `{"release_id":"release","name":"` + strings.Repeat(" ", 65536) + `Candidate"}`}
	for _, field := range []string{"build_ids", "artifact_ids", "sbom_ids", "scan_ids", "vex_ids", "contract_ids", "bundle_ids"} {
		for _, value := range []string{`null`, `[null]`, `[1]`, `[" "]`, `["bad\u0000id"]`} {
			bad = append(bad, `{"release_id":"release","name":"Candidate","`+field+`":`+value+`}`)
		}
	}
	for _, body := range bad {
		postRaw(t, s, secret, "/v1/release-candidates", "invalid", []byte(body), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("malformed input reached commands", f)
	}
}

func TestCandidateCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base, secret := testServer(t)
			p := postJSON(t, base, secret, "/v1/products", "parent", map[string]any{"name": "Parent", "slug": "parent"}, 201)
			release := postJSON(t, base, secret, "/v1/releases", "release", map[string]any{"product_id": dataField(t, p, "id"), "version": "1"}, 201)
			f := &candidateCreationHTTPFake{}
			s := base
			if native {
				var err error
				s, err = newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{CandidateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
				assertNoAggregateServerDependencies(t, s)
			}
			body := `{"release_id":"` + dataField(t, release, "id") + `","name":"Snapshot"}`
			for n, tc := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				r := httptest.NewRequest("POST", "https://api.example/v1/release-candidates", strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", n))
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				before := f.calls + f.guards
				s.Handler().ServeHTTP(w, r)
				if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != f.calls+f.guards {
					t.Fatal("unsafe candidate cookie mutation", w.Code, w.Body.String())
				}
			}
		})
	}
}
