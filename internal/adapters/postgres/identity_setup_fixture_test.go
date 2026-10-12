package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Test setup composes real focused commands over the explicitly supplied
// factory. It does not construct a Ledger or publish aggregate caches.
type postgresIdentitySetupFixture struct {
	factory     app.UnitOfWorkFactory
	credentials *identityapp.HMACAuthenticationCredentials
	clock       application.Clock
}

func postgresIdentitySetup(factory app.UnitOfWorkFactory, pepper string) postgresIdentitySetupFixture {
	credentials, err := identityapp.NewHMACAuthenticationCredentials(pepper)
	if err != nil {
		panic("invalid identity fixture credentials")
	}
	return postgresIdentitySetupFixture{factory, credentials, application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })}
}

func (f postgresIdentitySetupFixture) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	if ctx == nil || f.factory == nil {
		return domain.Tenant{}, domain.APIKey{}, "", app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	identity, err := identityapp.NewTenantBootstrapCommands(identityapp.TenantBootstrapConfig{Credentials: f.credentials, Clock: f.clock, IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
	}
	signing, err := verificationapp.NewInitialSigningKeyCommands(verificationapp.InitialSigningKeyConfig{KeyFactory: localed25519.KeyFactory{}, Clock: f.clock})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
	}
	prepared, err := identity.PrepareTenantBootstrap(ctx, identityapp.BootstrapTenantInput{TenantName: name, APIKeyName: keyName, Scopes: scopes})
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
	}
	key, err := signing.PrepareInitialSigningKey(ctx, prepared.Tenant.ID)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
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
	if err := identity.CommitTenantBootstrap(ctx, postgresBootstrapIdentityWriter{r.Identity, r.Audit}, prepared); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
	}
	if err := signing.CommitInitialSigningKey(ctx, postgresBootstrapSigningWriter{r.Signatures}, prepared.Tenant.ID, key); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", postgresIdentityFixtureError(err)
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

func (f postgresIdentitySetupFixture) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	if ctx == nil {
		return domain.Actor{}, app.ErrValidation
	}
	reader, hasReader := f.factory.(identityapp.AuthenticationReader)
	activity, hasActivity := f.factory.(identityapp.AuthenticationActivity)
	if hasReader || hasActivity {
		if !hasReader || !hasActivity {
			return domain.Actor{}, app.ErrValidation
		}
		auth, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: reader, Activity: activity, Credentials: f.credentials, Clock: f.clock})
		if err != nil {
			return domain.Actor{}, postgresIdentityFixtureError(err)
		}
		actor, err := auth.Authenticate(ctx, secret)
		return actor, postgresIdentityFixtureError(err)
	}
	// The memory regression backend supplies current transaction-owned reads
	// and writes. This path is not PostgreSQL durability or locking evidence.
	var actor domain.Actor
	err := app.ExecuteUnitOfWork(ctx, f.factory, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityapp.AuthenticationReader)
		if !ok {
			return app.ErrValidation
		}
		auth, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: reader, Activity: postgresFixtureIdentityActivity{r.Identity}, Credentials: f.credentials, Clock: f.clock})
		if err != nil {
			return postgresIdentityFixtureError(err)
		}
		actor, err = auth.Authenticate(ctx, secret)
		return postgresIdentityFixtureError(err)
	})
	if err != nil {
		return domain.Actor{}, err
	}
	return actor, nil
}

type postgresBootstrapIdentityWriter struct {
	identity app.IdentityRepository
	audit    app.AuditRepository
}

func (w postgresBootstrapIdentityWriter) InsertTenant(ctx context.Context, tenant identitydomain.Tenant) error {
	return w.identity.InsertTenant(ctx, domain.Tenant{ID: tenant.ID, Name: tenant.Name, CreatedAt: tenant.CreatedAt})
}
func (w postgresBootstrapIdentityWriter) InsertAPIKey(ctx context.Context, key identitydomain.APIKey) error {
	return w.identity.InsertAPIKey(ctx, domain.APIKey(key))
}
func (w postgresBootstrapIdentityWriter) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (postgresRedactionFixtureTransaction{audit: w.audit}).AppendAudit(ctx, e)
}

type postgresBootstrapSigningWriter struct{ signatures app.SignatureRepository }

func (w postgresBootstrapSigningWriter) InsertSigningKey(ctx context.Context, p verificationapp.PreparedSigningKey) error {
	k := p.Key
	return w.signatures.InsertSigningKey(ctx, domain.SigningKey{ID: k.ID, TenantID: k.TenantID, KID: k.KID, Version: k.Version, Provider: k.Provider, Algorithm: k.Algorithm, Status: k.Status.String(), PublicKey: k.PublicKey, PublicKeyFingerprint: k.PublicKeyFingerprint, Private: p.PrivateMaterial, ValidFrom: k.ValidFrom, ValidUntil: k.ValidUntil, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt, RevocationReason: k.RevocationReason, RevocationSemantics: k.RevocationSemantics, HistoricalValidityPolicy: k.HistoricalValidityPolicy, CompromisedAt: k.CompromisedAt})
}

type postgresFixtureIdentityActivity struct{ identity app.IdentityRepository }

func (a postgresFixtureIdentityActivity) RecordAPIKeyUse(ctx context.Context, key identitydomain.APIKey, activity identityapp.CollectorActivity) error {
	writer, ok := a.identity.(interface {
		RecordAPIKeyUse(context.Context, identitydomain.APIKey, identityapp.CollectorActivity) error
	})
	if !ok {
		return app.ErrValidation
	}
	return writer.RecordAPIKeyUse(ctx, key, activity)
}
func (a postgresFixtureIdentityActivity) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, expected identityapp.SessionIdentity, clock application.Clock) (time.Time, error) {
	reader, ok := a.identity.(interface {
		SessionIdentity(context.Context, identitydomain.SSOSession) (identityapp.SessionIdentity, error)
	})
	if !ok {
		return time.Time{}, app.ErrValidation
	}
	current, err := reader.SessionIdentity(ctx, session)
	if err != nil {
		return time.Time{}, err
	}
	if !identityapp.SameSessionIdentity(current, expected) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err := a.identity.ValidateActiveSSOSession(ctx, domain.SSOSession(session), clock.Now().UTC()); err != nil {
		return time.Time{}, err
	}
	metadataReader, ok := a.identity.(identityapp.SSOSessionRevocationReader)
	if !ok {
		return time.Time{}, app.ErrValidation
	}
	metadata, err := metadataReader.ReadSSOSessionForRevocation(ctx, session.TenantID, session.ID)
	if err != nil {
		return time.Time{}, err
	}
	if metadata.LastUsedAt == nil {
		return time.Time{}, app.ErrValidation
	}
	return metadata.LastUsedAt.UTC(), nil
}

func postgresIdentityFixtureError(err error) error {
	switch {
	case errors.Is(err, identityapp.ErrValidation), errors.Is(err, verificationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, identityapp.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, identityapp.ErrForbidden), errors.Is(err, verificationapp.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, identityapp.ErrNotFound), errors.Is(err, verificationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, identityapp.ErrConflict), errors.Is(err, verificationapp.ErrConflict):
		return app.ErrConflict
	default:
		return err
	}
}
