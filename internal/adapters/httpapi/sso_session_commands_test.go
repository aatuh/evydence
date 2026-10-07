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

type sessionHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	input            identityapp.CreateSSOSessionInput
	guardErr, runErr error
}

func (f *sessionHTTPFake) AuthorizeCreateSSOSession(_ context.Context, a identitydomain.Actor, in identityapp.CreateSSOSessionInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}
func (f *sessionHTTPFake) CreateSSOSession(_ context.Context, a identitydomain.Actor, in identityapp.CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	f.calls++
	f.actor, f.input = a, in
	return identitydomain.SSOSession{ID: "session", TenantID: a.TenantID, UserID: in.UserID, ProviderID: in.ProviderID, Prefix: "public-prefix", ExpiresAt: in.ExpiresAt, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), SchemaVersion: identitydomain.SSOSessionSchemaVersion}, "evysso_private-fixture", f.runErr
}
func TestSSOSessionHTTPUsesFocusedIssuanceAndStrictDecoder(t *testing.T) {
	base, secret := testServer(t)
	f := &sessionHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOSessionCommands: f}); err == nil {
		t.Fatal("session issuance retained Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SSOSessionCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"user_id":"user","provider_id":"provider","expires_at":"2026-10-04T01:02:03Z"}`
	postRaw(t, s, "", "/v1/sso/sessions", "unauth-session", []byte(body), 401)
	bad := []string{"null", "[]", `{`, `{} {}`, `{"unknown":true}`, `{"user_id":"user","user_id":"other"}`, `{"expires_at":"not-date"}`, strings.Repeat(" ", 65537) + body, `{"user_id":"` + string([]byte{0xff}) + `"}`}
	for _, field := range []string{"user_id", "provider_id", "expires_at"} {
		bad = append(bad, `{"`+field+`":null}`)
	}
	for i, b := range bad {
		postRaw(t, s, secret, "/v1/sso/sessions", fmt.Sprintf("bad-session-%d", i), []byte(b), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("bad session JSON reached issuer")
	}
	out := postRaw(t, s, secret, "/v1/sso/sessions", "valid-session", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || f.actor.TenantID == "" || f.actor.KeyID == "" || f.input.UserID != "user" || f.input.ProviderID != "provider" || f.input.ExpiresAt.IsZero() {
		t.Fatal("session actor/input mapping lost")
	}
	for _, field := range []string{`"id":"session"`, `"schema_version":"sso-session.v1.0.0"`, `"secret":"evysso_private-fixture"`} {
		if !strings.Contains(out, field) {
			t.Fatal("session creation field lost", field)
		}
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private session storage"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/sso/sessions", fmt.Sprintf("%s-session-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private session storage") || strings.Contains(out, "evysso_private-fixture") || strings.Contains(out, `"id":"session"`) || stage == "guard" && f.calls != before {
				t.Fatal("failed issuance leaked secret or invoked issuer")
			}
		}
	}
}
