package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Focused issuance joins the actual fixture command transaction. Credential
// and time dependencies are explicit; guards never read key inventories.
type apiKeyFixtureCommands struct {
	catalogFixtureCommands
	credentials identityapp.APIKeyCredentials
	clock       application.Clock
}

func (f apiKeyFixtureCommands) AuthorizeCreateAPIKey(ctx context.Context, actor identitydomain.Actor, input identityapp.CreateAPIKeyInput) error {
	commands, err := f.nativeCommands(true)
	if err != nil {
		return err
	}
	return commands.AuthorizeCreateAPIKey(ctx, actor, input)
}

func (f apiKeyFixtureCommands) CreateAPIKey(ctx context.Context, actor identitydomain.Actor, input identityapp.CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	c, err := f.nativeCommands(false)
	if err != nil {
		return identitydomain.APIKey{}, "", err
	}
	value, secret, err := c.CreateAPIKey(ctx, actor, input)
	return value, secret, providerVerificationFixtureError(err)
}

func (f apiKeyFixtureCommands) nativeCommands(readOnly bool) (*identityapp.APIKeyCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	c := f.credentials
	if readOnly {
		c = apiKeyFixtureNoIssuance{}
	} else {
		if c == nil {
			c = fixtureSessionCredentials("test")
		}
		if f.clock != nil {
			clock = f.clock
		}
	}
	return identityapp.NewAPIKeyCommands(identityapp.APIKeyCommandConfig{Transactions: apiKeyFixtureGuardTransactions{f.catalogFixtureCommands, readOnly}, Credentials: c, Authorizer: identityapp.NewAPIKeyWriteAuthorizer(), Clock: clock, IDs: ids})
}

type apiKeyFixtureGuardTransactions struct {
	catalogFixtureCommands
	readOnly bool
}

func (f apiKeyFixtureGuardTransactions) ExecuteAPIKey(ctx context.Context, tenant string, run func(context.Context, identityapp.APIKeyTransaction) error) error {
	return ssoExchangeNativeError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityapp.APIKeyWriteReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		if err := reader.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return run(ctx, apiKeyFixtureGuardTransaction{r, f.readOnly})
	}))
}

type apiKeyFixtureGuardTransaction struct {
	repos    app.Repositories
	readOnly bool
}

func (f apiKeyFixtureGuardTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return identityapp.NewAPIKeyWriteAuthorizer().Authorize(ctx, actor, request)
}

// The guard fails closed if a future preflight attempts credential issuance or
// any write. Only the legacy clone's real command may issue in these fixtures.
func (f apiKeyFixtureGuardTransaction) InsertAPIKey(ctx context.Context, v identitydomain.APIKey) error {
	if f.readOnly {
		panic("API-key guard inserted credential")
	}
	return f.repos.Identity.InsertAPIKey(ctx, domain.APIKey(v))
}
func (f apiKeyFixtureGuardTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.readOnly {
		panic("API-key guard appended audit")
	}
	return (portalFixtureTransaction{repos: f.repos}).AppendAudit(ctx, v)
}

type apiKeyFixtureNoIssuance struct{}

func (apiKeyFixtureNoIssuance) Generate() (identityapp.Credential, error) {
	panic("API-key guard minted credential")
}

func (s *Server) bindAPIKeyFixturePort(ledger *app.Ledger) {
	if old, fixture := s.apiKeyCommands.(apiKeyFixtureCommands); fixture {
		old.ledger = ledger
		s.apiKeyCommands = old
	} else if s.apiKeyCommands == nil {
		s.apiKeyCommands = apiKeyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	}
}

func (s *Server) bindAPIKeyFixtureResources(pepper string, clock application.Clock) {
	if f, ok := s.apiKeyCommands.(apiKeyFixtureCommands); ok {
		f.credentials, f.clock = fixtureSessionCredentials(pepper), clock
		s.apiKeyCommands = f
	}
	switch f := s.authn.(type) {
	case ssoFixtureAuthenticator:
		s.authn = fixtureIdentityAuthenticator(f.ledger, pepper, clock)
	case identityNativeFixtureAuthenticator:
		s.authn = fixtureIdentityAuthenticator(f.ledger, pepper, clock)
	}
}

var _ APIKeyCommands = apiKeyFixtureCommands{}

func apiKeyTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, secret := identityTestServer(t)
	s.bindAPIKeyFixtureResources("test", nil)
	return s, secret
}

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
	commands := apiKeyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
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

func TestAPIKeyFixtureGuardUsesRepositoryTenantWithoutCredentialInventory(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		return r.Identity.InsertTenant(ctx, domain.Tenant{ID: "repository-tenant", Name: "Repository Tenant", CreatedAt: peripheralFixtureQueryClock()})
	}); err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f := apiKeyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "repository-tenant", KeyID: "authenticated-admin", Scopes: []string{"*"}}
	if err := f.AuthorizeCreateAPIKey(t.Context(), actor, identityapp.CreateAPIKeyInput{Name: "Collector", Scopes: []string{"evidence:write"}}); err != nil {
		t.Fatal("guard required cached tenant or bootstrap credential inventory", err)
	}
	if err := (collectorFixtureGuard{catalogFixtureCommands{ledger: ledger}}).LockCollectorWrites(t.Context(), actor.TenantID); err != nil {
		t.Fatal("collector tenant guard required credential inventory", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("API-key guard changed repository state", err)
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
	commands := &failingAPIKeyFixtureCommand{apiKeyFixtureCommands: apiKeyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}}
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
	if _, err := fixtureIdentityAuthenticator(ledger, "fixture-pepper", providerVerificationFixtureClock()).Authenticate(t.Context(), commands.secret); !errors.Is(err, app.ErrUnauthorized) {
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
	server.apiKeyCommands = apiKeyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}
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
