package wiring

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestMemoryAPIKeyCommandsUseRealPreflightWithoutIssuingCredentials(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Tenant", CreatedAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildAPIKeyCommands(factory, "fixture-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", KeyID: "admin", Scopes: []string{"*"}}
	input := identityapp.CreateAPIKeyInput{Name: "Collector", Scopes: []string{"evidence:write"}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeCreateAPIKey(t.Context(), actor, input); err != nil {
		t.Fatal("real preflight could not use the memory fixture", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("credential preflight wrote fixture state", err)
	}
	unknown := actor
	unknown.TenantID = "unknown"
	if err := commands.AuthorizeCreateAPIKey(t.Context(), unknown, input); !errors.Is(err, identityapp.ErrNotFound) {
		t.Fatal("preflight accepted an unknown tenant", err)
	}
	denied := actor
	denied.Scopes = []string{"evidence:write"}
	if err := commands.AuthorizeCreateAPIKey(t.Context(), denied, input); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("preflight skipped administrator scope", err)
	}
	input.Scopes = []string{"instance:admin"}
	if err := commands.AuthorizeCreateAPIKey(t.Context(), actor, input); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("tenant wildcard granted instance authority", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := commands.AuthorizeCreateAPIKey(ctx, actor, input); !errors.Is(err, context.Canceled) {
		t.Fatal("preflight ignored cancellation", err)
	}
	after, err = factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("rejected preflight wrote fixture state", err)
	}
	input.Scopes = []string{"evidence:write"}
	key, secret, err := commands.CreateAPIKey(t.Context(), actor, input)
	if err != nil || key.ID == "" || key.TenantID != actor.TenantID || key.Hash != "" || secret == "" {
		t.Fatal("focused command could not issue a public credential", err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("fixture-pepper")
	if err != nil {
		t.Fatal(err)
	}
	after, err = factory.Snapshot()
	stored := after.APIKeys[key.ID]
	if err != nil || len(after.APIKeys) != 1 || stored.Hash != credentials.Hash(secret) || stored.Prefix != credentials.Prefix(secret) || stored.Hash == secret || len(after.AuditEntries[actor.TenantID]) != 1 {
		t.Fatal("focused issuance lost private storage or atomic audit", err)
	}
}
