package wiring

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

// TenantBootstrapCommands is startup-only composition. Each context receives
// only its own flat write capability, not the other context or a Ledger.
type TenantBootstrapCommands struct {
	factory  app.UnitOfWorkFactory
	identity *identityapp.TenantBootstrapCommands
	signing  *verificationapp.InitialSigningKeyCommands
}

type TenantBootstrapResult struct {
	Created bool
	Tenant  identitydomain.Tenant
	Key     identitydomain.APIKey
	Secret  string `json:"-"`
}

func BuildTenantBootstrapCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*TenantBootstrapCommands, error) {
	if factory == nil {
		return nil, app.ErrValidation
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	clock := application.ClockFunc(time.Now)
	identity, err := identityapp.NewTenantBootstrapCommands(identityapp.TenantBootstrapConfig{Credentials: credentials, Clock: clock, IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return nil, err
	}
	signing, err := verificationapp.NewInitialSigningKeyCommands(verificationapp.InitialSigningKeyConfig{KeyFactory: localed25519.KeyFactory{}, Clock: clock})
	if err != nil {
		return nil, err
	}
	return &TenantBootstrapCommands{factory, identity, signing}, nil
}

type tenantBootstrapGuard interface {
	LockAndCheckTenantBootstrap(context.Context) (bool, error)
}

// BootstrapFirstTenant owns a top-level startup transaction rather than joining
// an ambient command. No public identity or bearer secret is returned before
// the transaction has committed. Existing installations return a zero result.
func (s *TenantBootstrapCommands) BootstrapFirstTenant(ctx context.Context, input identityapp.BootstrapTenantInput) (TenantBootstrapResult, error) {
	if ctx == nil || s == nil {
		return TenantBootstrapResult{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return TenantBootstrapResult{}, err
	}
	uow, err := s.factory.BeginUnitOfWork(ctx)
	if err != nil {
		return TenantBootstrapResult{}, mapTenantBootstrapError(err)
	}
	if uow == nil {
		return TenantBootstrapResult{}, app.ErrValidation
	}
	committed := false
	defer func() {
		if !committed {
			_ = uow.Rollback(context.WithoutCancel(ctx))
		}
	}()
	repos := uow.Repositories()
	guard, ok := repos.Identity.(tenantBootstrapGuard)
	if !ok || repos.Signatures == nil || repos.Audit == nil {
		return TenantBootstrapResult{}, app.ErrValidation
	}
	exists, err := guard.LockAndCheckTenantBootstrap(ctx)
	if err != nil {
		return TenantBootstrapResult{}, mapTenantBootstrapError(err)
	}
	var identity identityapp.PreparedTenantBootstrap
	if !exists {
		identity, err = s.identity.PrepareTenantBootstrap(ctx, input)
		if err != nil {
			return TenantBootstrapResult{}, mapTenantBootstrapError(err)
		}
		signing, err := s.signing.PrepareInitialSigningKey(ctx, identity.Tenant.ID)
		if err != nil {
			return TenantBootstrapResult{}, mapTenantBootstrapError(err)
		}
		defer clear(signing.PrivateMaterial)
		if err := s.identity.CommitTenantBootstrap(ctx, tenantBootstrapIdentityWriter{apiKeyTransaction{repos.Identity, repos.Audit}}, identity); err != nil {
			return TenantBootstrapResult{}, mapTenantBootstrapError(err)
		}
		if err := s.signing.CommitInitialSigningKey(ctx, initialSigningKeyWriter{repos.Signatures}, identity.Tenant.ID, signing); err != nil {
			return TenantBootstrapResult{}, mapTenantBootstrapError(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return TenantBootstrapResult{}, err
	}
	if err := uow.Commit(ctx); err != nil {
		return TenantBootstrapResult{}, mapTenantBootstrapError(err)
	}
	committed = true
	if exists {
		return TenantBootstrapResult{}, nil
	}
	tenant, key, secret := identity.PublicResult()
	return TenantBootstrapResult{Created: true, Tenant: tenant, Key: key, Secret: secret}, nil
}

type tenantBootstrapIdentityWriter struct{ apiKeyTransaction }

func (w tenantBootstrapIdentityWriter) InsertTenant(ctx context.Context, tenant identitydomain.Tenant) error {
	writer, ok := w.identity.(interface {
		InsertTenant(context.Context, domain.Tenant) error
	})
	if !ok {
		return identityapp.ErrValidation
	}
	return mapAPIKeyWriteError(writer.InsertTenant(ctx, domain.Tenant{ID: tenant.ID, Name: tenant.Name, CreatedAt: tenant.CreatedAt}))
}

type initialSigningKeyWriter struct{ signatures app.SignatureRepository }

func (w initialSigningKeyWriter) InsertSigningKey(ctx context.Context, prepared verificationapp.PreparedSigningKey) error {
	key := signingKeyToLegacy(prepared.Key)
	key.Private = prepared.PrivateMaterial
	return mapSigningKeyWriteError(w.signatures.InsertSigningKey(ctx, key))
}

func mapTenantBootstrapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, app.ErrValidation), errors.Is(err, identityapp.ErrValidation), errors.Is(err, verificationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, app.ErrConflict), errors.Is(err, identityapp.ErrConflict), errors.Is(err, verificationapp.ErrConflict):
		return app.ErrConflict
	default:
		return errors.New("tenant bootstrap transaction failed")
	}
}
