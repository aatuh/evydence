package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type tenantBootstrapNativeFixture struct {
	factory     app.UnitOfWorkFactory
	credentials identityapp.CredentialManager
	clock       application.Clock
}

func (f tenantBootstrapNativeFixture) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	if ctx == nil || f.factory == nil {
		return domain.Tenant{}, domain.APIKey{}, "", app.ErrValidation
	}
	prepared, err := f.prepare(ctx, name, keyName, scopes)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	defer clear(prepared.key.PrivateMaterial)
	uow, err := f.factory.BeginUnitOfWork(ctx)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	if uow == nil {
		return domain.Tenant{}, domain.APIKey{}, "", app.ErrValidation
	}
	committed := false
	defer func() {
		if !committed {
			_ = uow.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err := prepared.commit(ctx, uow.Repositories()); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	if err := uow.Commit(ctx); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	committed = true
	return prepared.publicResult()
}

// BootstrapTestTenant uses the test's root context, never a nested command's
// context. The supplied real executor must commit before returning; fixture
// secrets are not released from an outer transaction that has yet to commit.
func (f tenantBootstrapNativeFixture) BootstrapTestTenant(t *testing.T, execute func(context.Context, app.UnitOfWorkCommand) error, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	t.Helper()
	if execute == nil {
		return domain.Tenant{}, domain.APIKey{}, "", app.ErrValidation
	}
	ctx := t.Context()
	prepared, err := f.prepare(ctx, name, keyName, scopes)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	defer clear(prepared.key.PrivateMaterial)
	if err := execute(ctx, prepared.commit); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	return prepared.publicResult()
}

type preparedTenantBootstrapFixture struct {
	identity *identityapp.TenantBootstrapCommands
	signing  *verificationapp.InitialSigningKeyCommands
	tenant   identityapp.PreparedTenantBootstrap
	key      verificationapp.PreparedSigningKey
}

func (f tenantBootstrapNativeFixture) prepare(ctx context.Context, name, keyName string, scopes []string) (preparedTenantBootstrapFixture, error) {
	if ctx == nil {
		return preparedTenantBootstrapFixture{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return preparedTenantBootstrapFixture{}, err
	}
	identity, err := identityapp.NewTenantBootstrapCommands(identityapp.TenantBootstrapConfig{Credentials: f.credentials, Clock: f.clock, IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return preparedTenantBootstrapFixture{}, providerVerificationFixtureError(err)
	}
	signing, err := verificationapp.NewInitialSigningKeyCommands(verificationapp.InitialSigningKeyConfig{KeyFactory: localed25519.KeyFactory{}, Clock: f.clock})
	if err != nil {
		return preparedTenantBootstrapFixture{}, mapVerificationCommandError(err)
	}
	tenant, err := identity.PrepareTenantBootstrap(ctx, identityapp.BootstrapTenantInput{TenantName: name, APIKeyName: keyName, Scopes: scopes})
	if err != nil {
		return preparedTenantBootstrapFixture{}, providerVerificationFixtureError(err)
	}
	key, err := signing.PrepareInitialSigningKey(ctx, tenant.Tenant.ID)
	if err != nil {
		return preparedTenantBootstrapFixture{}, mapVerificationCommandError(err)
	}
	return preparedTenantBootstrapFixture{identity, signing, tenant, key}, nil
}

func (p preparedTenantBootstrapFixture) commit(ctx context.Context, r app.Repositories) error {
	if r.Identity == nil || r.Signatures == nil || r.Audit == nil {
		return app.ErrValidation
	}
	if err := p.identity.CommitTenantBootstrap(ctx, tenantBootstrapFixtureIdentityWriter{apiKeyFixtureGuardTransaction{repos: r}}, p.tenant); err != nil {
		return providerVerificationFixtureError(err)
	}
	if err := p.signing.CommitInitialSigningKey(ctx, signingAdminFixtureTransaction{signatures: r.Signatures}, p.tenant.Tenant.ID, p.key); err != nil {
		return mapVerificationCommandError(err)
	}
	return ctx.Err()
}

func (p preparedTenantBootstrapFixture) publicResult() (domain.Tenant, domain.APIKey, string, error) {
	tenant, public, secret := p.tenant.PublicResult()
	return domain.Tenant{ID: tenant.ID, Name: tenant.Name, CreatedAt: tenant.CreatedAt}, domain.APIKey(public), secret, nil
}

type tenantBootstrapFixtureIdentityWriter struct{ apiKeyFixtureGuardTransaction }

func (w tenantBootstrapFixtureIdentityWriter) InsertTenant(ctx context.Context, tenant identitydomain.Tenant) error {
	return w.repos.Identity.InsertTenant(ctx, domain.Tenant{ID: tenant.ID, Name: tenant.Name, CreatedAt: tenant.CreatedAt})
}

// Repository-backed transport fixtures bootstrap through the real context
// commands and authenticate current rows. Cache-only negative fixtures do not
// use this setup, and no configuration is read from private Ledger state.
func repositoryBootstrapTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test", UnitOfWork: factory})
	clock := application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("test"), clock}
	_, _, secret, err := bootstrap.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	auth := fixtureIdentityAuthenticator(ledger, "test", clock)
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.bindAPIKeyFixtureResources("test", clock)
	return server, secret
}
