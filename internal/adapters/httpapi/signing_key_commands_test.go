package httpapi

import (
	"context"
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

type signingKeyHTTPFake struct {
	rotations, revocations int
	guards                 int
	guardErr               error
	err                    error
}

func (f *signingKeyHTTPFake) AuthorizeSigningKeyRotation(context.Context, identitydomain.Actor) error {
	f.guards++
	return f.guardErr
}
func (f *signingKeyHTTPFake) AuthorizeSigningKeyRevocation(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}

func (f *signingKeyHTTPFake) RotateSigningKey(_ context.Context, actor identitydomain.Actor, _ string) (verificationdomain.SigningKey, error) {
	f.rotations++
	status, _ := verificationdomain.ParseSigningKeyStatus("active")
	return verificationdomain.SigningKey{ID: "key_focused", TenantID: actor.TenantID, Version: 2, Status: status, PublicKey: "public"}, f.err
}
func (f *signingKeyHTTPFake) RevokeSigningKey(_ context.Context, actor identitydomain.Actor, id string, input verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	f.revocations++
	status, _ := verificationdomain.ParseSigningKeyStatus("revoked")
	return verificationdomain.SigningKey{ID: id, TenantID: actor.TenantID, Status: status, RevocationReason: input.Reason}, f.err
}
func TestSigningKeyHandlersUseFocusedCommandsAndReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &signingKeyHTTPFake{}
	server.signingKeyCommands = commands
	server.durableCommandExecutor = newTrustHTTPReplayExecutor(t, server, secret)
	input := map[string]any{"reason": "scheduled"}
	response := postJSON(t, server, secret, "/v1/signing-keys/rotate", "focused-rotate", input, http.StatusCreated)
	if dataField(t, response, "id") != "key_focused" || dataField(t, response, "status") != "active" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, "/v1/signing-keys/rotate", "focused-rotate", input, http.StatusCreated))
	if commands.rotations != 1 {
		t.Fatal("rotation replay reran command")
	}
	response = postJSON(t, server, secret, "/v1/signing-keys/key_focused/revoke", "focused-revoke", input, http.StatusOK)
	if dataField(t, response, "status") != "revoked" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, "/v1/signing-keys/key_focused/revoke", "focused-revoke", input, http.StatusOK))
	if commands.revocations != 1 {
		t.Fatal("revocation replay reran command")
	}
	for i, bad := range []string{`{}`, `null`, `{"reason":null}`, `{"reason":" "}`, `{"reason":1}`, `{"reason":"a","reason":"b"}`, `{"reason":"a","unknown":true}`, `[]`, `{} {}`} {
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key_focused/revoke"} {
			postRaw(t, server, secret, path, "bad-key-"+string(rune('a'+i))+path, []byte(bad), http.StatusBadRequest)
		}
	}
	if commands.rotations != 1 || commands.revocations != 1 {
		t.Fatal("malformed input reached key commands")
	}
	for i, bad := range []string{`{"reason":"incident","semantics":null}`, `{"reason":"incident","historical_validity_policy":null}`} {
		postRaw(t, server, secret, "/v1/signing-keys/key_focused/revoke", "bad-null-key-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.revocations != 1 {
		t.Fatal("null lifecycle policy reached key command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{application.ErrForbidden, http.StatusForbidden}, {verificationapp.ErrNotFound, http.StatusNotFound}, {verificationapp.ErrConflict, http.StatusConflict}, {errors.New("private SQL and key material"), http.StatusInternalServerError}} {
		commands.err = tc.err
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key_focused/revoke"} {
			response := postJSON(t, server, secret, path, "error-key-"+string(rune('a'+i))+path, input, tc.status)
			if strings.Contains(response, "private SQL") || strings.Contains(response, `"data"`) {
				t.Fatal("key command error leaked internal data", response)
			}
		}
	}
}

func TestSigningKeyHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &signingKeyHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SigningKeyCommands: f}); err == nil {
		t.Fatal("focused signing keys accepted Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SigningKeyCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	for _, route := range []struct {
		path   string
		status int
	}{{"/v1/signing-keys/rotate", 201}, {"/v1/signing-keys/key_focused/revoke", 200}} {
		const body = `{"reason":"scheduled"}`
		one := postRaw(t, s, secret, route.path, "native", []byte(body), route.status)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, route.path, "native", []byte(body), route.status))
		postRaw(t, s, secret, route.path, "native", []byte(`{"reason":"different"}`), 409)
		f.guardErr = application.ErrForbidden
		postRaw(t, s, secret, route.path, "native", []byte(body), 403)
		f.guardErr = nil
	}
	if f.rotations != 1 || f.revocations != 1 || f.guards != 8 {
		t.Fatal("replay bypassed current authorization or reran lifecycle", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private-key SQL password=secret"), 500}} {
		f.guardErr = tc.err
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key_focused/revoke"} {
			before := f.rotations + f.revocations
			out := postRaw(t, s, secret, path, fmt.Sprintf("guard-error-%d", i), []byte(`{"reason":"scheduled"}`), tc.status)
			if f.rotations+f.revocations != before || strings.Contains(out, "private-key") || strings.Contains(out, `"data"`) {
				t.Fatal("guard failed open or leaked", out)
			}
		}
	}
}

func TestSigningKeyHTTPStrictFieldsBeforeFixtureAndNativeCommands(t *testing.T) {
	for _, focused := range []bool{false, true} {
		s, secret := testServer(t)
		f := &signingKeyHTTPFake{}
		if focused {
			s.signingKeyCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for _, path := range []string{"/v1/signing-keys/rotate", "/v1/signing-keys/key/revoke"} {
			bad := []string{`{"REASON":"scheduled"}`, `{"reason":"a","REASON":"b"}`, `{"reason":"bad\u0000"}`, `{"reason":"` + strings.Repeat(" ", 4096) + `a"}`, `{"reason":"` + string([]byte{255}) + `"}`, strings.Repeat(" ", 65537)}
			if strings.HasSuffix(path, "/revoke") {
				bad = append(bad, `{"reason":"incident","semantics":"unknown"}`, `{"reason":"incident","semantics":"ordinary","historical_validity_policy":"invalidate_all"}`, `{"reason":"incident","semantics":"`+strings.Repeat(" ", 64)+`ordinary"}`)
			}
			for i, body := range bad {
				postRaw(t, s, secret, path, fmt.Sprintf("strict-%d", i), []byte(body), 400)
			}
		}
		postRaw(t, s, secret, "/v1/signing-keys/"+strings.Repeat("k", 1025)+"/revoke", "long-id", []byte(`{"reason":"incident"}`), 400)
		if f.guards+f.rotations+f.revocations != 0 {
			t.Fatal("malformed input reached native lifecycle")
		}
	}
}

func TestSigningKeyHTTPFixtureAndNativeCookieAndReplayAuthority(t *testing.T) {
	for _, focused := range []bool{false, true} {
		base, secret := testServer(t)
		f := &signingKeyHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.SigningKeyCommands = f
			opts.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/signing-keys/rotate", strings.NewReader(`{"reason":"scheduled"}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.guards + f.rotations
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && before != f.guards+f.rotations {
				t.Fatal("unsafe cookie key mutation", focused, w.Code, w.Body.String())
			}
		}
	}
	base, secret := testServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"reason":"scheduled"}`
	one := postRaw(t, s, secret, "/v1/signing-keys/rotate", "local", []byte(body), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/signing-keys/rotate", "local", []byte(body), 201))
	path := "/v1/signing-keys/" + dataField(t, one, "id") + "/revoke"
	revoked := postRaw(t, s, secret, path, "local-revoke", []byte(body), 200)
	assertTrustHTTPReplay(t, revoked, postRaw(t, s, secret, path, "local-revoke", []byte(body), 200))
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/signing-keys/rotate", "local", []byte(body), 403)
	postRaw(t, s, secret, path, "local-revoke", []byte(body), 403)
}
