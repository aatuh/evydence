package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type samlBindingHTTPStub struct {
	guards, writes, reads int
	actor                 identitydomain.Actor
	id                    string
	input                 identityapp.ConfigureSAMLProviderBindingInput
	fail                  error
}

func (f *samlBindingHTTPStub) AuthorizeConfigureSAMLProviderBinding(_ context.Context, a identitydomain.Actor, id string, in identityapp.ConfigureSAMLProviderBindingInput) error {
	f.guards++
	f.actor, f.id, f.input = a, id, in
	return f.fail
}
func (f *samlBindingHTTPStub) ConfigureSAMLProviderBinding(_ context.Context, a identitydomain.Actor, id string, in identityapp.ConfigureSAMLProviderBindingInput) (identitydomain.SAMLProviderBinding, error) {
	f.writes++
	f.actor, f.id, f.input = a, id, in
	return f.value(), f.fail
}
func (f *samlBindingHTTPStub) GetSAMLProviderBinding(_ context.Context, a identitydomain.Actor, id string) (identitydomain.SAMLProviderBinding, error) {
	f.reads++
	f.actor, f.id = a, id
	return f.value(), f.fail
}
func (f *samlBindingHTTPStub) value() identitydomain.SAMLProviderBinding {
	return identitydomain.SAMLProviderBinding{TenantID: f.actor.TenantID, ProviderID: f.id, Recipient: "https://sp.example.test/consume", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: time.Now().UTC(), Provider: identitydomain.SSOProvider{SAMLSigningCertificates: []string{"internal-provider-snapshot-canary"}}}
}

func TestSAMLProviderBindingHTTPUsesFocusedCommandsAndExplicitProjection(t *testing.T) {
	base, secret := testServer(t)
	f := &samlBindingHTTPStub{}
	s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{SAMLProviderBindingCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/sso/providers/provider/saml-binding"
	for i, body := range []string{`null`, `[]`, `{`, `{} {}`, `{"recipient":null}`, `{"recipient":"https://sp.example.test/consume","recipient":"https://foreign.example.test"}`, `{"recipient":"https://sp.example.test/consume","extra":true}`, `{"recipient":"https://sp.example.test/consume","name_id_format":null}`, `{"Recipient":"https://sp.example.test/consume"}`, `{"recipient":"https://sp.example.test/consume","name_id_format":""}`, `{"recipient":"https://sp.example.test/consume","name_id_format":" "}`} {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-saml-binding-%d", i), []byte(body), 400)
	}
	if f.guards+f.writes != 0 {
		t.Fatal("invalid configuration reached focused commands")
	}
	postRaw(t, s, "", path, "unauth-saml-binding", []byte(`{"recipient":"https://sp.example.test/consume"}`), 401)
	out := postRaw(t, s, secret, path, "saml-binding-create", []byte(`{"recipient":"https://sp.example.test/consume"}`), 200)
	if f.guards != 1 || f.writes != 1 || f.actor.TenantID == "" || f.id != "provider" || f.input.Recipient != "https://sp.example.test/consume" || strings.Contains(out, "internal-provider-snapshot-canary") || strings.Contains(out, `"provider":`) || !strings.Contains(out, `"schema_version":"saml-provider-binding.v1.0.0"`) {
		t.Fatal("binding route lost scoped path/input or exposed internal snapshot")
	}
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || f.reads != 1 || strings.Contains(w.Body.String(), "internal-provider-snapshot-canary") {
		t.Fatal("binding read failed or exposed internal trust", w.Code)
	}
	f.fail = application.ErrForbidden
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("binding read ignored current command authorization", w.Code)
	}
	f.fail = errors.New("private binding storage canary")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 500 || strings.Contains(w.Body.String(), "private binding storage canary") || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("binding read exposed private storage error", w.Code)
	}
	if _, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{SAMLProviderBindingCommands: f}); err == nil {
		t.Fatal("binding configuration accepted missing durable executor")
	}
}

func TestSAMLPublicLoginRouteDeclaresProviderTenantPolicy(t *testing.T) {
	f := &samlRequestTransportStub{}
	base, _ := testServer(t)
	s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{SAMLAuthenticationRequestCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/sso/saml-authentication-requests", strings.NewReader(`{"provider_id":"provider"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated || f.calls != 1 {
		t.Fatal("public SAML initiation required unrelated credentials", w.Code)
	}
	p, ok := authorizationPolicyForOperation("beginSAMLAuthentication")
	if !ok || p.Mode != "public-login-state" || p.TenantRule != "configured-provider-tenant" {
		t.Fatal("SAML public state route lost configured tenant policy")
	}
}
