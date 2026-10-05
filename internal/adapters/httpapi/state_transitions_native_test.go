package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type candidateStateHTTPFake struct {
	calls, guards int
	guardErr      error
}

func (f *candidateStateHTTPFake) AuthorizeCandidateTransition(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}
func (f *candidateStateHTTPFake) UpdateReleaseCandidateState(_ context.Context, a identitydomain.Actor, id, state, _ string, rev int64) (releasedomain.ReleaseCandidate, error) {
	f.calls++
	v, _ := releasedomain.ParseReleaseCandidateState(state)
	return releasedomain.ReleaseCandidate{ID: id, TenantID: a.TenantID, ReleaseID: "release", State: v, Revision: rev + 1}, nil
}

func stateTransitionRawHTTP(t *testing.T, s *Server, secret, path, key, tag, body string, want int) string {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("If-Match", tag)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("transition %s status=%d want=%d: %s", path, w.Code, want, w.Body.String())
	}
	return w.Body.String()
}
func TestStateTransitionsRequireNativeReplayAndCurrentGuard(t *testing.T) {
	for _, kind := range []string{"freeze", "approve", "promote", "reject"} {
		t.Run(kind, func(t *testing.T) {
			base, secret := testServer(t)
			r, c := &releaseStateHTTPFake{}, &candidateStateHTTPFake{}
			o := ServerOptions{}
			path, body, tag := "/v1/releases/release/"+kind, `{}`, `"1"`
			if kind == "approve" {
				tag = `"2"`
			}
			if kind == "freeze" || kind == "approve" {
				o.ReleaseStateCommands = r
			} else {
				o.CandidateStateCommands = c
				path = "/v1/release-candidates/candidate/" + kind
				body = `{"reason":"reviewed"}`
			}
			if s, err := NewServerWithOptions(base.ledger, o); err == nil || s != nil {
				t.Error("focused state transition accepted aggregate replay")
			}
			o.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
			s, err := NewServerWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger = nil
			one := stateTransitionRawHTTP(t, s, secret, path, "current", tag, body, 200)
			assertTrustHTTPReplay(t, one, stateTransitionRawHTTP(t, s, secret, path, "current", tag, body, 200))
			stateTransitionRawHTTP(t, s, secret, path, "current", `"3"`, body, 409)
			stateTransitionRawHTTP(t, s, secret, path, "current", tag, body+" ", 409)
			before := r.guards + c.guards
			for _, invalid := range []string{"", `W/"1"`, `"01"`, `"+1"`, `"0"`, `"9223372036854775808"`, `"1", "2"`} {
				stateTransitionRawHTTP(t, s, secret, path, "current", invalid, body, 400)
			}
			if r.guards+c.guards != before {
				t.Fatal("invalid If-Match reached current guard")
			}
			r.guardErr, c.guardErr = application.ErrForbidden, application.ErrForbidden
			stateTransitionRawHTTP(t, s, secret, path, "current", tag, body, 403)
			if r.calls+c.calls != 1 || r.guards+c.guards != 5 {
				t.Fatal("transition replay skipped current authority", r, c)
			}
		})
	}
}

func TestStateTransitionsCookieOriginAndBearerPrecedenceBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, kind := range []string{"freeze", "approve", "promote", "reject"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, kind), func(t *testing.T) {
				base, secret := testServer(t)
				p := postJSON(t, base, secret, "/v1/products", "parent", map[string]any{"name": "Parent", "slug": "parent"}, 201)
				release := postJSON(t, base, secret, "/v1/releases", "release", map[string]any{"product_id": dataField(t, p, "id"), "version": "1"}, 201)
				id := dataField(t, release, "id")
				path, body, tag := "/v1/releases/"+id+"/"+kind, `{}`, `"1"`
				if kind == "approve" {
					postJSONWithIfMatch(t, base, secret, "/v1/releases/"+id+"/freeze", "prepare", 1, map[string]any{}, 200)
					tag = `"2"`
				}
				if kind == "promote" || kind == "reject" {
					candidate := postJSON(t, base, secret, "/v1/release-candidates", "candidate", map[string]any{"release_id": id, "name": "Snapshot"}, 201)
					path = "/v1/release-candidates/" + dataField(t, candidate, "id") + "/" + kind
					body = `{"reason":"Reviewed"}`
				}
				r, c := &releaseStateHTTPFake{}, &candidateStateHTTPFake{}
				s := base
				if native {
					var err error
					s, err = NewServerWithOptions(base.ledger, ServerOptions{ReleaseStateCommands: r, CandidateStateCommands: c, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
					if err != nil {
						t.Fatal(err)
					}
					s.ledger = nil
				}
				for _, tc := range []struct {
					origin string
					bearer bool
					want   int
				}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 200}, {"https://attacker.example", true, 200}} {
					req := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(body))
					req.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
					req.Header.Set("Origin", tc.origin)
					req.Header.Set("Idempotency-Key", "cookie-action")
					req.Header.Set("If-Match", tag)
					if tc.bearer {
						req.Header.Set("Authorization", "Bearer "+secret)
					}
					w := httptest.NewRecorder()
					before := r.calls + c.calls + r.guards + c.guards
					s.Handler().ServeHTTP(w, req)
					if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != r.calls+c.calls+r.guards+c.guards {
						t.Fatal("unsafe state cookie mutation", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}
func TestStateTransitionPreflightRejectsInvalidBodiesBeforeWrites(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate=%t", candidate), func(t *testing.T) {
			base, secret := testServer(t)
			r, c := &releaseStateHTTPFake{}, &candidateStateHTTPFake{}
			s, err := NewServerWithOptions(base.ledger, ServerOptions{ReleaseStateCommands: r, CandidateStateCommands: c, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/releases/release/freeze"
			bad := []string{`null`, `[]`, `{"unknown":true}`, `{} {}`}
			if candidate {
				path = "/v1/release-candidates/candidate/promote"
				bad = []string{`{"Reason":"reviewed"}`, `{"reason":null}`, `{"reason":"bad\u0000reason"}`, `{"reason":"reviewed","extra":true}`}
			}
			for n, body := range bad {
				stateTransitionRawHTTP(t, s, secret, path, fmt.Sprintf("invalid-%d", n), `"1"`, body, 400)
			}
			if r.calls+c.calls+r.guards+c.guards != 0 {
				t.Fatal("malformed body reached transition", r, c)
			}
		})
	}
}

func TestStateTransitionNativeFingerprintKeepsHistoricalConditionalRecords(t *testing.T) {
	base, secret := testServer(t)
	commands := &releaseStateHTTPFake{}
	executor := newTrustHTTPReplayExecutor(t, base, secret)
	s, err := NewServerWithOptions(base.ledger, ServerOptions{ReleaseStateCommands: commands, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger = nil
	a, err := s.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/releases/release/freeze"
	r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
	r.Header.Set("If-Match", `"1"`)
	input, err := conditionalActionFingerprint(r, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key   string
		input []byte
	}{{"historical", input}, {"body-only", []byte(`{}`)}} {
		if _, _, err := executor.WithBody(t.Context(), a, "POST", path, c.key, c.input, func(context.Context) error { return nil }, func(context.Context) (int, any, error) {
			return 200, map[string]any{"id": "historical", "revision": json.Number("9007199254740993")}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	out := stateTransitionRawHTTP(t, s, secret, path, "historical", `"1"`, `{}`, 200)
	if !strings.Contains(out, "9007199254740993") {
		t.Fatal("historical conditional response changed", out)
	}
	stateTransitionRawHTTP(t, s, secret, path, "body-only", `"1"`, `{}`, 409)
	if commands.calls != 0 || commands.guards != 2 {
		t.Fatal("historical replay ran transition or omitted authority", commands)
	}
}

func TestReleaseTransitionDecoderPreservesEmptyAndBlankBodyCompatibility(t *testing.T) {
	for _, body := range []string{"", " \n\t", `{}`, " \n{}\n"} {
		r := httptest.NewRequest("POST", "/v1/releases/release/freeze", nil)
		r.SetPathValue("id", "release")
		r.Header.Set("If-Match", `"1"`)
		id, rev, err := decodeReleaseTransition(r, []byte(body))
		if err != nil || id != "release" || rev != 1 {
			t.Fatal("legacy valid empty body rejected", body, id, rev, err)
		}
	}
}
