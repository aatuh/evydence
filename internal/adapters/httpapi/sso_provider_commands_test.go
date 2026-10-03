package httpapi

import (
	"context"
	"encoding/json"
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
	id               string
	trust            identityapp.UpdateSSOProviderTrustMaterialInput
}

func TestSSODiscoveryOpenAPIDescribesOptionalEmptyObjectBody(t *testing.T) {
	s, _ := testServer(t)
	encoded, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Required bool `json:"required"`
				Content  map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths["/v1/sso/providers/{id}/discover-oidc"]["post"]
	if op.RequestBody.Required || op.RequestBody.Content["application/json"].Schema.Ref != "#/components/schemas/EmptyObject" {
		t.Fatal("discovery OpenAPI rejects the supported omitted body or permits an unrelated request")
	}
}

func (f *ssoProviderHTTPFake) AuthorizeRefreshSSOProviderOIDCTrustMaterial(_ context.Context, a identitydomain.Actor, id string) error {
	f.guards++
	f.actor, f.id = a, id
	return f.guardErr
}

func (f *ssoProviderHTTPFake) RefreshSSOProviderOIDCTrustMaterial(_ context.Context, a identitydomain.Actor, id string) (identitydomain.SSOProvider, error) {
	f.calls++
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	return identitydomain.SSOProvider{ID: id, TenantID: a.TenantID, Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", RoleMapping: map[string]string{"token-reviewers": "security_engineer"}, Status: "active", SchemaVersion: identitydomain.SSOProviderSchemaVersion, CreatedAt: now, TrustMaterialUpdatedAt: &now}, f.runErr
}

func TestSSODiscoveryHTTPUsesFocusedCommandAndRejectsNonemptyOrMalformedBody(t *testing.T) {
	base, secret := testServer(t)
	f := &ssoProviderHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOProviderCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/sso/providers/provider/discover-oidc"
	for i, bad := range []string{"null", "[]", `{`, `{} {}`, `{"extra":true}`, `{"jwks":{"keys":[]}}`, `{"bad":"` + string([]byte{0xff}) + `"}`, strings.Repeat(" ", 65537) + `{}`} {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-discovery-%d", i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid discovery body reached focused port")
	}
	postRaw(t, s, "", path, "unauth-discovery", []byte(`{}`), 401)
	for i, body := range []string{`{}`, ""} {
		out := postRaw(t, s, secret, path, fmt.Sprintf("discovery-%d", i), []byte(body), 200)
		if f.id != "provider" || f.actor.TenantID == "" || !strings.Contains(out, "trust_material_updated_at") {
			t.Fatal("discovery path/actor/DTO mapping lost")
		}
	}
	for i, ec := range []struct {
		err    error
		status int
	}{
		{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409},
		{identityapp.ErrVerificationFailed, 422}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private discovery storage"), 500},
	} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-discovery-%d", phase, i), []byte(`{}`), ec.status)
			if phase == "guard" && f.calls != before || strings.Contains(out, "private discovery storage") || strings.Contains(out, "issuer.example.test") {
				t.Fatal("discovery failure ignored guard or exposed private metadata")
			}
		}
	}
}

func (f *ssoProviderHTTPFake) AuthorizeUpdateSSOProviderTrustMaterial(_ context.Context, a identitydomain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) error {
	f.guards++
	f.actor, f.id, f.trust = a, id, in
	return f.guardErr
}
func (f *ssoProviderHTTPFake) UpdateSSOProviderTrustMaterial(_ context.Context, a identitydomain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	f.calls++
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return identitydomain.SSOProvider{ID: id, TenantID: a.TenantID, Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", JWKS: in.JWKS, SAMLSigningCertificates: in.SAMLSigningCertificates, TrustMaterialUpdatedAt: &now, Status: "active", SchemaVersion: identitydomain.SSOProviderSchemaVersion, CreatedAt: now}, f.runErr
}

func TestSSOTrustHTTPDispatchesFocusedCommandAndStrictJSON(t *testing.T) {
	base, secret := testServer(t)
	f := &ssoProviderHTTPFake{}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOProviderCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/sso/providers/provider/trust-material"
	const body = `{"jwks":{"keys":[{"kty":"OKP","kid":"fixture","crv":"Ed25519","x":"public-only"}]}}`
	for i, bad := range []string{"null", "[]", `{`, `{} {}`, `{"extra":true}`, `{"jwks":null}`, `{"jwks":{},"jwks":{}}`, `{"saml_signing_certificates":null}`, `{"saml_signing_certificates":[null]}`, `{"jwks":{"kid":"` + string([]byte{0xff}) + `"}}`, strings.Repeat(" ", 65537) + body} {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-trust-%d", i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid trust request reached focused port")
	}
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, path, "trust-rotation", []byte(body), 200)
	if f.guards != 1 || f.calls != 1 || f.id != "provider" || !strings.Contains(out, `"trust_material_updated_at"`) || !strings.Contains(out, `"x":"public-only"`) {
		t.Fatal("trust input or DTO mapping lost")
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private trust SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-trust-%d", phase, i), []byte(body), ec.status)
			if phase == "guard" && f.calls != before || strings.Contains(out, "private trust SQL") || strings.Contains(out, "public-only") || strings.Contains(out, "issuer.example.test") {
				t.Fatal("trust guard bypassed or failure leaked internals")
			}
		}
	}
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
