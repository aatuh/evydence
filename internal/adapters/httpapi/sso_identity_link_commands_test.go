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

func TestSSOIdentityLinkOpenAPIRequiresVerifiedAssertion(t *testing.T) {
	s, _ := testServer(t)
	encoded, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []any `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	values := doc.Components.Schemas["LinkSSOIdentityRequest"].Properties["verified"].Enum
	if len(values) != 1 || values[0] != true {
		t.Fatal("identity-link contract advertises unsupported unverified links")
	}
}

type identityLinkHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	input            identityapp.LinkSSOIdentityInput
	guardErr, runErr error
}

func (f *identityLinkHTTPFake) AuthorizeLinkSSOIdentity(_ context.Context, a identitydomain.Actor, in identityapp.LinkSSOIdentityInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}
func (f *identityLinkHTTPFake) LinkSSOIdentity(_ context.Context, a identitydomain.Actor, in identityapp.LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	f.calls++
	f.actor, f.input = a, in
	return identitydomain.UserIdentityLink{ID: "link", TenantID: a.TenantID, UserID: in.UserID, ProviderID: in.ProviderID, Subject: in.Subject, Email: in.Email, Verified: in.Verified, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, f.runErr
}
func TestSSOIdentityLinkHTTPUsesFocusedCommandAndStrictDecoder(t *testing.T) {
	base, secret := testServer(t)
	f := &identityLinkHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOIdentityLinkCommands: f}); err == nil {
		t.Fatal("identity links retained Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOIdentityLinkCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"user_id":"user","provider_id":"provider","subject":"subject","email":"person@example.test","verified":true}`
	postRaw(t, s, "", "/v1/sso/identity-links", "unauth", []byte(body), 401)
	bad := []string{"null", "[]", `{`, `{} {}`, `{"unknown":true}`, `{"verified":true,"verified":false}`, strings.Repeat(" ", 65537) + body, `{"subject":"` + string([]byte{0xff}) + `"}`}
	for _, field := range []string{"user_id", "provider_id", "subject", "email", "verified"} {
		bad = append(bad, `{"`+field+`":null}`)
	}
	for i, b := range bad {
		postRaw(t, s, secret, "/v1/sso/identity-links", fmt.Sprintf("bad-link-%d", i), []byte(b), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("invalid link body reached command")
	}
	out := postRaw(t, s, secret, "/v1/sso/identity-links", "valid-link", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || f.actor.KeyID == "" || f.actor.TenantID == "" || f.input.UserID != "user" || f.input.ProviderID != "provider" || f.input.Subject != "subject" || f.input.Email != "person@example.test" || !f.input.Verified {
		t.Fatal("link request/actor mapping lost")
	}
	for _, field := range []string{`"id":"link"`, `"email":"person@example.test"`, `"verified":true`, `"schema_version":"user-identity-link.v1.0.0"`} {
		if !strings.Contains(out, field) {
			t.Fatal("link DTO field lost", field)
		}
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private link storage"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/sso/identity-links", fmt.Sprintf("%s-link-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private link storage") || strings.Contains(out, `"id":"link"`) || stage == "guard" && f.calls != before {
				t.Fatal("unsafe link failure")
			}
		}
	}
}
