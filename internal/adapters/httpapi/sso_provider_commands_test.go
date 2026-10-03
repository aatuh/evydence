package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type ssoProviderHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	input            identityapp.CreateSSOProviderInput
	guardErr, runErr error
}

func (f *ssoProviderHTTPFake) AuthorizeCreateSSOProvider(_ context.Context, a identitydomain.Actor, in identityapp.CreateSSOProviderInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}
func (f *ssoProviderHTTPFake) CreateSSOProvider(_ context.Context, a identitydomain.Actor, in identityapp.CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	f.calls++
	return identitydomain.SSOProvider{ID: "sso", TenantID: a.TenantID, Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: in.GroupsClaim, RoleMapping: in.RoleMapping, JWKS: in.JWKS, SAMLSigningCertificates: in.SAMLSigningCertificates, Status: "active", SchemaVersion: identitydomain.SSOProviderSchemaVersion, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, f.runErr
}
func TestSSOProviderHTTPDispatchesFocusedCommandsAndStrictJSON(t *testing.T) {
	base, secret := testServer(t)
	f := &ssoProviderHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOProviderCommands: f}); err == nil {
		t.Fatal("provider commands silently kept Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOProviderCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/sso/providers"
	const body = `{"name":"Example","type":"oidc","issuer":"https://issuer.example.test","client_id":"client","groups_claim":"groups","role_mapping":{"maintainers":"tenant_admin"},"jwks":{"keys":[]},"saml_signing_certificates":[]}`
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	for i, bad := range []string{"null", "[]", `{`, `{} {}`, `{"extra":true}`, `{"name":"A","name":"B"}`, `{"role_mapping":{"a":"collector","a":"tenant_admin"}}`, `{"role_mapping":{"group":null}}`, `{"saml_signing_certificates":[null]}`, `{"name":"` + string([]byte{0xff}) + `"}`, strings.Repeat(" ", 65537) + body} {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-provider-%d", i), []byte(bad), 400)
	}
	for _, field := range []string{"name", "type", "issuer", "client_id", "groups_claim", "role_mapping", "jwks", "saml_signing_certificates"} {
		postRaw(t, s, secret, path, "null-"+field, []byte(`{"`+field+`":null}`), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid provider body reached commands")
	}
	out := postRaw(t, s, secret, path, "valid-provider", []byte(body), 201)
	if f.guards != 1 || f.calls != 1 || f.actor.TenantID == "" || f.actor.KeyID == "" || f.input.GroupsClaim != "groups" || f.input.RoleMapping["maintainers"] != "tenant_admin" || !strings.Contains(out, `"schema_version":"`+identitydomain.SSOProviderSchemaVersion+`"`) || !strings.Contains(out, `"client_id":"client"`) {
		t.Fatal("provider DTO or request mapping lost")
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private provider SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-provider-%d", phase, i), []byte(body), ec.status)
			if strings.Contains(out, "private provider SQL") || strings.Contains(out, "issuer.example.test") || phase == "guard" && before != f.calls {
				t.Fatal("unsafe provider failure or ignored guard")
			}
		}
	}
}
