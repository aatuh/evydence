package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Legacy HTTP fixtures still issue through their isolated command clone. The
// preflight uses the real focused policy and validation, never a no-op guard.
// These adapters are test-only; PostgreSQL remains the runtime's scoped reader.
type apiKeyFixtureCommands struct{ catalogFixtureCommands }

func (f apiKeyFixtureCommands) AuthorizeCreateAPIKey(ctx context.Context, actor identitydomain.Actor, input identityapp.CreateAPIKeyInput) error {
	if ctx == nil {
		return identityapp.ErrValidation
	}
	commands, err := identityapp.NewAPIKeyCommands(identityapp.APIKeyCommandConfig{
		Transactions: apiKeyFixtureGuardTransactions{ledger: f.commandLedger(ctx)},
		Credentials:  apiKeyFixtureNoIssuance{},
		Authorizer:   identityapp.NewAPIKeyWriteAuthorizer(),
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
	if err != nil {
		return err
	}
	return commands.AuthorizeCreateAPIKey(ctx, actor, input)
}

func (f apiKeyFixtureCommands) CreateAPIKey(ctx context.Context, actor identitydomain.Actor, input identityapp.CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	value, secret, err := f.commandLedger(ctx).CreateAPIKey(ctx, actor, input.Name, input.Scopes, input.ExpiresAt)
	return identitydomain.APIKey(value), secret, err
}

type apiKeyFixtureGuardTransactions struct{ ledger *app.Ledger }

func (f apiKeyFixtureGuardTransactions) ExecuteAPIKey(ctx context.Context, tenant string, run func(context.Context, identityapp.APIKeyTransaction) error) error {
	if ctx == nil || f.ledger == nil || run == nil {
		return identityapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run(ctx, apiKeyFixtureGuardTransaction{ledger: f.ledger, tenant: tenant}); err != nil {
		return err
	}
	return ctx.Err()
}

type apiKeyFixtureGuardTransaction struct {
	ledger *app.Ledger
	tenant string
}

func (f apiKeyFixtureGuardTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := identityapp.NewAPIKeyWriteAuthorizer().Authorize(ctx, actor, request); err != nil {
		return err
	}
	if actor.TenantID != f.tenant {
		return identityapp.ErrNotFound
	}
	// Every legacy fixture tenant is created by BootstrapTenant and retains its
	// bootstrap key. The authorized read checks that real fixture ownership;
	// it does not synthesize a tenant or add a production inventory query.
	keys, err := f.ledger.ListAPIKeys(ctx, actor)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.TenantID == actor.TenantID {
			return nil
		}
	}
	return identityapp.ErrNotFound
}

// The guard fails closed if a future preflight attempts credential issuance or
// any write. Only the legacy clone's real command may issue in these fixtures.
func (apiKeyFixtureGuardTransaction) InsertAPIKey(context.Context, identitydomain.APIKey) error {
	return identityapp.ErrValidation
}
func (apiKeyFixtureGuardTransaction) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	return application.AuditReceipt{}, identityapp.ErrValidation
}

type apiKeyFixtureNoIssuance struct{}

func (apiKeyFixtureNoIssuance) Generate() (identityapp.Credential, error) {
	return identityapp.Credential{}, identityapp.ErrValidation
}

func (s *Server) bindAPIKeyFixturePort(ledger *app.Ledger) {
	if _, fixture := s.apiKeyCommands.(apiKeyFixtureCommands); s.apiKeyCommands == nil || fixture {
		s.apiKeyCommands = apiKeyFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	}
}

var _ APIKeyCommands = apiKeyFixtureCommands{}

func TestAPIKeyFixtureGuardUsesRealPolicyWithoutIssuance(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Fixture", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	commands := apiKeyFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	input := identityapp.CreateAPIKeyInput{Name: "Collector", Scopes: []string{"evidence:write"}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeCreateAPIKey(t.Context(), actor, input); err != nil {
		t.Fatal("real guard rejected the fixture administrator", err)
	}
	var missingContext context.Context
	if err := commands.AuthorizeCreateAPIKey(missingContext, actor, input); !errors.Is(err, identityapp.ErrValidation) {
		t.Fatal("fixture guard accepted a missing context", err)
	}
	for _, tc := range []struct {
		name  string
		actor domain.Actor
		input identityapp.CreateAPIKeyInput
		want  error
	}{
		{"unknown tenant", domain.Actor{TenantID: "unknown", KeyID: "admin", Scopes: []string{"*"}}, input, identityapp.ErrNotFound},
		{"not administrator", domain.Actor{TenantID: actor.TenantID, KeyID: actor.KeyID, Scopes: []string{"evidence:write"}}, input, application.ErrForbidden},
		{"instance escalation", actor, identityapp.CreateAPIKeyInput{Name: "Instance", Scopes: []string{" instance:admin "}}, application.ErrForbidden},
		{"empty name", actor, identityapp.CreateAPIKeyInput{Scopes: []string{"evidence:write"}}, identityapp.ErrValidation},
		{"empty scopes", actor, identityapp.CreateAPIKeyInput{Name: "Collector"}, identityapp.ErrValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := commands.AuthorizeCreateAPIKey(t.Context(), tc.actor, tc.input); !errors.Is(err, tc.want) {
				t.Fatal("fixture guard bypassed focused policy", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := commands.AuthorizeCreateAPIKey(ctx, actor, input); !errors.Is(err, context.Canceled) {
		t.Fatal("fixture guard ignored cancellation", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("fixture preflight issued or wrote repository state", err)
	}
}

type failingAPIKeyFixtureCommand struct {
	apiKeyFixtureCommands
	createdID string
	secret    string
	isolated  bool
}

func (f *failingAPIKeyFixtureCommand) CreateAPIKey(ctx context.Context, actor identitydomain.Actor, input identityapp.CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	f.isolated = f.commandLedger(ctx) != f.ledger
	key, secret, err := f.apiKeyFixtureCommands.CreateAPIKey(ctx, actor, input)
	if err != nil {
		return key, secret, err
	}
	f.createdID, f.secret = key.ID, secret
	return key, secret, errors.New("private fixture credential failure")
}

func TestAPIKeyFixtureReplayRollsBackFailedIssuanceAndRechecksAuthority(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Fixture", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	// Keep authentication heartbeat writes out of the issuance snapshot proof.
	// The actor was authenticated above; credential authentication is tested
	// separately for the rolled-back issued secret below.
	auth := &configuredAuthenticator{actor: actor}
	server.authn = auth
	commands := &failingAPIKeyFixtureCommand{apiKeyFixtureCommands: apiKeyFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
	server.apiKeyCommands = commands
	body := []byte(`{"name":"Rollback","scopes":["evidence:read"]}`)
	out := postRaw(t, server, secret, "/v1/api-keys", "fixture-credential-failure", body, 500)
	if commands.createdID == "" || commands.secret == "" || !commands.isolated || strings.Contains(out, commands.secret) || strings.Contains(out, commands.createdID) || strings.Contains(out, "private fixture") {
		t.Fatal("failed issuance bypassed isolation or exposed a credential")
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before.APIKeys, after.APIKeys) || !reflect.DeepEqual(before.AuditEntries, after.AuditEntries) {
		t.Fatal("failed issuance committed credentials or audit", err)
	}
	if _, err := ledger.Authenticate(t.Context(), commands.secret); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("rolled-back credential authenticated", err)
	}
	if len(after.Idempotency) != 1 {
		t.Fatal("failed issuance lost its replay failure record")
	}
	for _, record := range after.Idempotency {
		if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
			t.Fatal("failed issuance stored a partial credential response")
		}
	}
	server.apiKeyCommands = apiKeyFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	postRaw(t, server, secret, "/v1/api-keys", "fixture-credential-success", body, 201)
	before, err = factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	auth.actor.Scopes = []string{"evidence:read"}
	postRaw(t, server, secret, "/v1/api-keys", "fixture-credential-success", body, 403)
	after, err = factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unauthorized replay changed credentials or replay state", err)
	}
}
