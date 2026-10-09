package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceCreationHTTPFake struct {
	calls    int
	guards   int
	guardErr error
	err      error
	input    integrationapp.CreateSourceRepositoryInput
}

func (f *sourceCreationHTTPFake) AuthorizeSourceRepositoryCreation(context.Context, identitydomain.Actor, integrationapp.CreateSourceRepositoryInput) error {
	f.guards++
	return f.guardErr
}

func TestSourceRepositoryCreationRequiresNativeDurableReplay(t *testing.T) {
	s, _ := testServer(t)
	if v, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(s), ServerOptions{SourceRepositoryCommands: &sourceCreationHTTPFake{}}); err == nil || v != nil {
		t.Fatal("focused repository creation accepted aggregate replay")
	}
}

func TestSourceRepositoryCreationChecksCurrentGuardBeforeReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &sourceCreationHTTPFake{}
	s.sourceRepositoryCommands = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	body := []byte(`{"project_id":"project","provider":"github","full_name":"org/api"}`)
	one := postRaw(t, s, secret, "/v1/source/repositories", "native", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/source/repositories", "native", body, 201))
	for _, tc := range []struct {
		err    error
		status int
	}{{app.ErrForbidden, 403}, {integrationapp.ErrNotFound, 404}, {errors.New("private-source password=secret"), 500}} {
		f.guardErr = tc.err
		out := postRaw(t, s, secret, "/v1/source/repositories", "native", body, tc.status)
		if strings.Contains(out, "private-source") || strings.Contains(out, `"data"`) || f.calls != 1 {
			t.Fatal("source replay bypassed current guard", out, f)
		}
	}
	if f.guards != 5 {
		t.Fatal("source replay skipped guards", f.guards)
	}
}

func TestSourceRepositoryCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &sourceCreationHTTPFake{}
		if native {
			s.sourceRepositoryCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			want   int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/source/repositories", strings.NewReader(fmt.Sprintf(`{"provider":"github","full_name":"org/api%d"}`, i)))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.calls + f.guards
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe source cookie mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func TestSourceRepositoryCreationNativeDoesNotUseLedger(t *testing.T) {
	base, secret := testServer(t)
	f := &sourceCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{SourceRepositoryCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	body := []byte(`{"provider":" github ","full_name":" org/api "}`)
	one := postRaw(t, s, secret, "/v1/source/repositories", "native", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/source/repositories", "native", body, 201))
	postRaw(t, s, secret, "/v1/source/repositories", "native", append(append([]byte(nil), body...), ' '), 409)
	if f.calls != 1 || f.guards != 3 || f.input.Provider != "github" || f.input.FullName != "org/api" {
		t.Fatal("native source used aggregate or lost normalization", f)
	}
}

func TestSourceRepositoryCreationRejectsMalformedBodiesBeforeGuard(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &sourceCreationHTTPFake{}
		if native {
			s.sourceRepositoryCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
			assertNoAggregateServerDependencies(t, s)
		}
		bad := []string{"", " ", "{", "[]", "null", "{} {}", string([]byte{0xff}), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), `{}`, `{"provider":"github","full_name":"a","provider":"gitlab"}`, `{"provider":"github","full_name":"a","tenant_id":"other"}`, `{"provider":"github","full_name":"a","clone_url":null}`, `{"provider":"github","full_name":"bad\u0000"}`, `{"provider":"github","full_name":"a","project_id":"` + strings.Repeat(" ", 1025) + `project"}`, `{"provider":"github","full_name":"` + strings.Repeat("x", 2305) + `"}`}
		for i, body := range bad {
			out := postRaw(t, s, secret, "/v1/source/repositories", fmt.Sprintf("bad-%d", i), []byte(body), 400)
			if f.calls+f.guards != 0 || strings.Contains(out, `"data"`) {
				t.Fatal("malformed source reached command", native, f, out)
			}
		}
	}
}

func (f *sourceCreationHTTPFake) CreateSourceRepository(_ context.Context, a identitydomain.Actor, in integrationapp.CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	f.calls++
	f.input = in
	return integrationdomain.SourceRepository{ID: "durable_repository", TenantID: a.TenantID, ProjectID: in.ProjectID, Provider: in.Provider, FullName: in.FullName, SchemaVersion: integrationdomain.SourceRepositorySchemaVersion}, f.err
}
func TestSourceRepositoryHTTPUsesFocusedCommandAndRejectsMalformedEnvelopes(t *testing.T) {
	local, secret := testServer(t)
	f := &sourceCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(local), ServerOptions{SourceRepositoryCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"project_id": "not-in-ledger", "provider": "github", "full_name": "org/api"}
	body := postJSON(t, s, secret, "/v1/source/repositories", "source-replay", in, 201)
	if !strings.Contains(body, `"id":"durable_repository"`) || f.calls != 1 || f.input.ProjectID != "not-in-ledger" {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/source/repositories", "source-replay", in, 201))
	if f.calls != 1 {
		t.Fatal("replay reran creation", f)
	}
	for i, raw := range []string{`null`, `[]`, `{"provider":null}`, `{"project_id":null}`, `{"clone_url":null}`, `{"unknown":true}`, `{"provider":"a","provider":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/source/repositories", fmt.Sprintf("bad-source-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("bad envelope reached source command", f.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {errors.New("private repository SQL"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/source/repositories", fmt.Sprintf("failed-source-%d", i), in, tc.status)
		if strings.Contains(body, "private repository SQL") || strings.Contains(body, "durable_repository") {
			t.Fatal(body)
		}
	}
}
func TestSourceRepositoryOpenAPIDeclaresOwnershipAndMetadataOnlyRecording(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/source/repositories", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"existing repository", "before metadata", "2304", "same transaction", "does not contact", "native durable replay", "before trimming", "completed replay", "Origin", "Local evaluation requires PostgreSQL", "there is no local-memory API path"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing source repository contract", description)
		}
	}
}
