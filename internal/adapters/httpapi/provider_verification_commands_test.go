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
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type providerReceiptHTTPFake struct {
	guards, calls    int
	in               identityapp.VerifyProviderIdentityInput
	guardErr, runErr error
}

func TestProviderReceiptHTTPCookieMutationRequiresSameHTTPSOrigin(t *testing.T) {
	base, secret := testServer(t)
	f := &providerReceiptHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{ProviderVerificationCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"provider_type":"oidc","provider_id":"provider","subject":"subject"}`
	request := func(origins []string, bearer bool, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://example.com/v1/provider-verifications", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		for _, origin := range origins {
			r.Header.Add("Origin", origin)
		}
		if bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		r.Header.Set("Idempotency-Key", "origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unsafe cookie receipt", origins, w.Code)
		}
	}
	for _, origins := range [][]string{nil, {"https://attacker.example"}, {"http://example.com"}, {"null"}, {"https://example.com/path"}, {"https://example.com", "https://attacker.example"}} {
		request(origins, false, 403)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("cross-origin request reached receipt port")
	}
	request([]string{"https://example.com"}, false, 201)
	request([]string{"https://attacker.example"}, true, 201)
	if f.calls != 2 {
		t.Fatal("same-origin cookie or explicit bearer failed")
	}
}

func (f *providerReceiptHTTPFake) AuthorizeVerifyProviderIdentity(_ context.Context, _ identitydomain.Actor, in identityapp.VerifyProviderIdentityInput) error {
	f.guards++
	f.in = in
	return f.guardErr
}
func (f *providerReceiptHTTPFake) VerifyProviderIdentity(_ context.Context, a identitydomain.Actor, in identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	f.calls++
	return identitydomain.ProviderVerification{ID: "receipt", TenantID: a.TenantID, ProviderID: in.ProviderID, ProviderType: in.ProviderType, Subject: in.Subject, Result: "not_evaluated", SchemaVersion: identitydomain.ProviderVerificationVersion}, f.runErr
}
func TestProviderReceiptHTTPUsesFocusedPortStrictJSONAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &providerReceiptHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{ProviderVerificationCommands: f}); err == nil {
		t.Fatal("receipt commands allowed without durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{ProviderVerificationCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/provider-verifications"
	const body = `{"provider_type":"oidc","provider_id":"provider","subject":"subject"}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"extra":true}`, `{"provider_id":null}`, `{"subject":null}`, `{"id_token":null}`, `{"access_token":null}`, `{"saml_assertion":null}`, `{"provider_type":null}`, `{"provider_id":"a","provider_id":"b"}`, `{"subject":"` + string([]byte{0xff}) + `"}`} {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("invalid JSON reached receipt command")
	}
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, path, "success", []byte(body), 201)
	if f.guards != 1 || f.calls != 1 || f.in.ProviderType != "oidc" || !strings.Contains(out, `"provider_id":"provider"`) || !strings.Contains(out, `"schema_version"`) || strings.Contains(out, `"ProviderID"`) {
		t.Fatal("focused receipt dispatch/DTO mapping failed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {identityapp.ErrVerificationFailed, 422}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private receipt SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", phase, i), []byte(body), ec.status)
			if phase == "guard" && f.calls != before || strings.Contains(out, "private receipt SQL") || strings.Contains(out, `"receipt"`) {
				t.Fatal("error leaked receipt or bypassed guard", out)
			}
		}
	}
}
