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

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type retentionHTTPFake struct {
	creates, verifies          int
	createGuards, verifyGuards int
	input                      verificationapp.CreateObjectRetentionPolicyInput
	err                        error
	guardErr                   error
}

func (f *retentionHTTPFake) AuthorizeCreateObjectRetentionPolicy(context.Context, identitydomain.Actor, verificationapp.CreateObjectRetentionPolicyInput) error {
	f.createGuards++
	return f.guardErr
}
func (f *retentionHTTPFake) AuthorizeVerifyObjectRetentionPolicy(context.Context, identitydomain.Actor, string) error {
	f.verifyGuards++
	return f.guardErr
}

func (f *retentionHTTPFake) CreateObjectRetentionPolicy(_ context.Context, actor identitydomain.Actor, input verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	f.creates++
	f.input = input
	return verificationdomain.ObjectRetentionPolicy{ID: "policy_focused", TenantID: actor.TenantID, Name: input.Name, Status: "configured"}, f.err
}
func (f *retentionHTTPFake) VerifyObjectRetentionPolicy(_ context.Context, actor identitydomain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	f.verifies++
	return verificationdomain.ObjectRetentionPolicy{ID: id, TenantID: actor.TenantID, Status: "not_verified", VerificationHash: "receipt"}, f.err
}
func TestRetentionHandlersUseFocusedCommandsAndReplayWithoutFallback(t *testing.T) {
	server, secret := testServer(t)
	commands := &retentionHTTPFake{}
	server.retentionCommands = commands
	server.durableCommandExecutor = newTrustHTTPReplayExecutor(t, server, secret)
	input := map[string]any{"name": "lock", "mode": "governance", "retention_days": 30}
	path := "/v1/object-retention-policies"
	response := postJSON(t, server, secret, path, "focused-retention-create", input, http.StatusCreated)
	if dataField(t, response, "id") != "policy_focused" || commands.input.Name != "lock" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, path, "focused-retention-create", input, http.StatusCreated))
	if commands.creates != 1 || commands.createGuards != 2 {
		t.Fatal("create replay reran command")
	}
	path += "/policy_focused/verify"
	response = postJSON(t, server, secret, path, "focused-retention-verify", map[string]any{}, http.StatusOK)
	if dataField(t, response, "verification_hash") != "receipt" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, path, "focused-retention-verify", map[string]any{}, http.StatusOK))
	if commands.verifies != 1 || commands.verifyGuards != 2 {
		t.Fatal("verify replay reran command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("provider password=private-secret"), 500}} {
		commands.err = tc.err
		for _, path := range []string{"/v1/object-retention-policies", "/v1/object-retention-policies/policy_focused/verify"} {
			body := input
			if strings.HasSuffix(path, "/verify") {
				body = map[string]any{}
			}
			response := postJSON(t, server, secret, path, "retention-error-"+string(rune('a'+i))+path, body, tc.status)
			if strings.Contains(response, "private-secret") || strings.Contains(response, `"data"`) {
				t.Fatal("error leaked or fell back", response)
			}
		}
	}
}
func TestRetentionHandlersRejectMalformedBodiesBeforeCommandsInBothProfiles(t *testing.T) {
	for _, focused := range []bool{false, true} {
		server, secret := testServer(t)
		commands := &retentionHTTPFake{}
		if focused {
			server.retentionCommands = commands
			server.durableCommandExecutor = newTrustHTTPReplayExecutor(t, server, secret)
		}
		for i, bad := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"name":null,"mode":"governance","retention_days":30}`, `{"name":"lock","mode":null,"retention_days":30}`, `{"name":"lock","mode":"governance","retention_days":null}`, `{"name":"lock","name":"other","mode":"governance","retention_days":30}`, `{"name":"lock","mode":"governance","retention_days":1.5}`, `{"name":"lock","mode":"governance","retention_days":9223372036854775808}`, `{"name":"lock","mode":"governance","retention_days":30,"object_key":null}`, `{"name":"lock","mode":"governance","retention_days":30,"object_prefix":null}`, `{"name":"lock","mode":"governance","retention_days":30,"require_legal_hold":null}`, `{"name":"lock","mode":"governance","retention_days":30,"max_verification_age_hours":null}`, `{"name":"lock","mode":"governance","retention_days":30,"max_verification_age_hours":0}`} {
			postRaw(t, server, secret, "/v1/object-retention-policies", "bad-create-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
		}
		for i, bad := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"mode":"governance"}`} {
			postRaw(t, server, secret, "/v1/object-retention-policies/missing/verify", "bad-verify-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
		}
		if commands.creates != 0 || commands.verifies != 0 {
			t.Fatal("malformed request reached focused command")
		}
	}
}

func TestRetentionHTTPNativeReplayRequiredAndLegacyDependenciesUnused(t *testing.T) {
	base, secret := testServer(t)
	f := &retentionHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{RetentionCommands: f}); err == nil {
		t.Fatal("retention accepted Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{RetentionCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.verification, s.idempotency = nil, nil, nil
	create := `{"name":" Lock ","mode":" governance ","retention_days":30}`
	postRaw(t, s, secret, "/v1/object-retention-policies", "create", []byte(create), 201)
	if f.input.Name != "Lock" || f.input.Mode != "governance" || f.input.MaxVerificationAgeHours != 24 || !strings.HasPrefix(f.input.ObjectPrefix, "tenants/") {
		t.Fatal("normalization/defaults lost")
	}
	postRaw(t, s, secret, "/v1/object-retention-policies/policy/verify", "verify", []byte(`{}`), 200)
	for _, route := range []struct{ path, body string }{{"/v1/object-retention-policies", create}, {"/v1/object-retention-policies/policy/verify", `{}`}} {
		for i, tc := range []struct {
			err    error
			status int
		}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private retention SQL password=secret"), 500}} {
			f.guardErr = tc.err
			before := f.creates + f.verifies
			out := postRaw(t, s, secret, route.path, fmt.Sprintf("guard-%d", i), []byte(route.body), tc.status)
			if f.creates+f.verifies != before || strings.Contains(out, "private retention") || strings.Contains(out, `"data"`) {
				t.Fatal("guard bypass or leak", out)
			}
		}
	}
}

func TestRetentionHTTPRawBoundsAliasesAndScopedObjectsInBothProfiles(t *testing.T) {
	for _, focused := range []bool{false, true} {
		s, secret := testServer(t)
		f := &retentionHTTPFake{}
		if focused {
			s.retentionCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		base := map[string]any{"name": "Lock", "mode": "governance", "retention_days": 30}
		bad := []string{strings.Repeat(" ", 65537), `{"name":"` + string([]byte{255}) + `","mode":"governance","retention_days":30}`}
		for _, field := range []string{"name", "mode", "object_prefix", "object_key", "retention_days", "require_legal_hold", "max_verification_age_hours"} {
			b, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			bad = append(bad, strings.TrimSuffix(string(b), "}")+fmt.Sprintf(",%q:null}", strings.ToUpper(field)))
		}
		for _, tc := range []struct {
			field string
			value any
		}{
			{"name", strings.Repeat(" ", 4096) + "Lock"}, {"name", strings.Repeat("é", 2049)}, {"name", " "}, {"name", "bad\x00"},
			{"mode", strings.Repeat(" ", 4096) + "governance"}, {"mode", "unsupported"}, {"object_prefix", strings.Repeat(" ", 4097)}, {"object_prefix", "tenants/foreign/"}, {"object_key", "tenants/foreign/raw/sample"}, {"object_key", "bad\x00"},
			{"retention_days", 0}, {"retention_days", 2147483648}, {"max_verification_age_hours", 8785}, {"require_legal_hold", true},
		} {
			fields := map[string]any{}
			for k, v := range base {
				fields[k] = v
			}
			fields[tc.field] = tc.value
			b, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			bad = append(bad, string(b))
		}
		for i, body := range bad {
			postRaw(t, s, secret, "/v1/object-retention-policies", fmt.Sprintf("strict-%d", i), []byte(body), 400)
		}
		for i, id := range []string{strings.Repeat("x", 1025), "bad%00id", strings.Repeat("%20", 1024) + "policy"} {
			postRaw(t, s, secret, "/v1/object-retention-policies/"+id+"/verify", fmt.Sprintf("bad-id-%d", i), []byte(`{}`), 400)
		}
		if f.creates+f.verifies+f.createGuards+f.verifyGuards != 0 {
			t.Fatal("bad retention input reached native commands")
		}
	}
}

func TestRetentionHTTPBothProfilesCookieGuardAndLocalReplayAuthority(t *testing.T) {
	base, secret := testServer(t)
	id := dataField(t, postJSON(t, base, secret, "/v1/object-retention-policies", "local-policy", map[string]any{"name": "Lock", "mode": "governance", "retention_days": 30}, 201), "id")
	for _, focused := range []bool{false, true} {
		f := &retentionHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.RetentionCommands = f
			opts.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range []struct {
			path, body string
			status     int
		}{{"/v1/object-retention-policies", `{"name":"Lock","mode":"governance","retention_days":30}`, 201}, {"/v1/object-retention-policies/" + id + "/verify", `{}`, 200}} {
			for i, tc := range []struct {
				origin string
				bearer bool
				denied bool
			}{{"", false, true}, {"https://attacker.example", false, true}, {"http://api.example", false, true}, {"https://api.example", false, false}, {"https://attacker.example", true, false}} {
				r := httptest.NewRequest("POST", "https://api.example"+route.path, strings.NewReader(route.body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				before := f.creates + f.verifies + f.createGuards + f.verifyGuards
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				want := route.status
				if tc.denied {
					want = 403
				}
				if w.Code != want || w.Header().Get("Set-Cookie") != "" || tc.denied && f.creates+f.verifies+f.createGuards+f.verifyGuards != before {
					t.Fatal("unsafe retention cookie mutation", w.Code, w.Body.String())
				}
			}
		}
	}
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"admin", "verify:read"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct {
		path, body string
		status     int
	}{{"/v1/object-retention-policies", `{"name":"Lock","mode":"governance","retention_days":30}`, 201}, {"/v1/object-retention-policies/" + id + "/verify", `{}`, 200}} {
		one := postRaw(t, s, secret, route.path, "local-replay", []byte(route.body), route.status)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, route.path, "local-replay", []byte(route.body), route.status))
		auth.actor.ResourceGrants = nil
		postRaw(t, s, secret, route.path, "local-replay", []byte(route.body), 403)
		auth.actor = a
	}
}
