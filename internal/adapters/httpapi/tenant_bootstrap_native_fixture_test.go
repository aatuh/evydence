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
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	identity, err := identityapp.NewTenantBootstrapCommands(identityapp.TenantBootstrapConfig{Credentials: f.credentials, Clock: f.clock, IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", providerVerificationFixtureError(err)
	}
	signing, err := verificationapp.NewInitialSigningKeyCommands(verificationapp.InitialSigningKeyConfig{KeyFactory: localed25519.KeyFactory{}, Clock: f.clock})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", mapVerificationCommandError(err)
	}
	prepared, err := identity.PrepareTenantBootstrap(ctx, identityapp.BootstrapTenantInput{TenantName: name, APIKeyName: keyName, Scopes: scopes})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", providerVerificationFixtureError(err)
	}
	key, err := signing.PrepareInitialSigningKey(ctx, prepared.Tenant.ID)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", mapVerificationCommandError(err)
	}
	defer clear(key.PrivateMaterial)
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
	r := uow.Repositories()
	if r.Identity == nil || r.Signatures == nil || r.Audit == nil {
		return domain.Tenant{}, domain.APIKey{}, "", app.ErrValidation
	}
	if err := identity.CommitTenantBootstrap(ctx, tenantBootstrapFixtureIdentityWriter{apiKeyFixtureGuardTransaction{repos: r}}, prepared); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", providerVerificationFixtureError(err)
	}
	if err := signing.CommitInitialSigningKey(ctx, signingAdminFixtureTransaction{signatures: r.Signatures}, prepared.Tenant.ID, key); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", mapVerificationCommandError(err)
	}
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	if err := uow.Commit(ctx); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	committed = true
	tenant, public, secret := prepared.PublicResult()
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
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
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
