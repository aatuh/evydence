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

type apiKeyHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	input            identityapp.CreateAPIKeyInput
	guardErr, runErr error
}

func (f *apiKeyHTTPFake) AuthorizeCreateAPIKey(_ context.Context, a identitydomain.Actor, in identityapp.CreateAPIKeyInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}
func (f *apiKeyHTTPFake) CreateAPIKey(_ context.Context, a identitydomain.Actor, in identityapp.CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	f.calls++
	f.actor, f.input = a, in
	return identitydomain.APIKey{ID: "key", TenantID: a.TenantID, Name: in.Name, Prefix: "evy_public01", Scopes: in.Scopes, CreatedAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC), ExpiresAt: in.ExpiresAt, Hash: "private-hash"}, "fixture-secret", f.runErr
}
func TestAPIKeyHTTPFocusedCommandGuardsStrictInputAndMapsPublicCredential(t *testing.T) {
	base, secret := testServer(t)
	f := &apiKeyHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{APIKeyCommands: f}); err == nil {
		t.Fatal("focused keys retained Ledger idempotency")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{APIKeyCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"Automation","scopes":["evidence:read"],"expires_at":"2027-01-02T03:04:05Z"}`)
	postRaw(t, s, "", "/v1/api-keys", "unauth", body, 401)
	for i, bad := range []string{"null", "[]", `{`, `{} {}`, `{"name":"Automation","scopes":["evidence:read"],"extra":true}`, `{"name":"A","name":"B","scopes":["x"]}`, `{"name":null,"scopes":["x"]}`, `{"name":"A","scopes":null}`, `{"name":"A","scopes":[null]}`, `{"name":"A","scopes":["x"],"expires_at":null}`, `{"name":"A","scopes":["x"],"expires_at":"not-time"}`, strings.Repeat(" ", 65537) + string(body)} {
		postRaw(t, s, secret, "/v1/api-keys", fmt.Sprintf("bad-key-%d", i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid input reached credential command")
	}
	out := postRaw(t, s, secret, "/v1/api-keys", "valid-key", body, 201)
	if f.guards != 1 || f.calls != 1 || f.actor.KeyID == "" || f.actor.TenantID == "" || f.input.Name != "Automation" || f.input.ExpiresAt == nil || len(f.input.Scopes) != 1 {
		t.Fatal("actor or credential request mapping lost")
	}
	for _, field := range []string{`"api_key"`, `"id":"key"`, `"prefix":"evy_public01"`, `"scopes":["evidence:read"]`, `"expires_at":"2027-01-02T03:04:05Z"`, `"secret":"fixture-secret"`} {
		if !strings.Contains(out, field) {
			t.Fatal("credential DTO field lost", field)
		}
	}
	if strings.Contains(out, "private-hash") {
		t.Fatal("credential hash exposed")
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private credential SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/api-keys", fmt.Sprintf("%s-key-%d", stage, i), body, ec.status)
			if strings.Contains(out, "private credential SQL") || strings.Contains(out, "fixture-secret") || stage == "guard" && f.calls != before {
				t.Fatal("unsafe credential failure")
			}
		}
	}
}
