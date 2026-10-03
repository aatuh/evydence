package app

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// bootstrapTenant composes Identity-owned credential preparation and
// Verification-owned signing-key preparation inside one durable unit of work.
// Neither context receives mutation authority over the other's repository.
func (l *Ledger) bootstrapTenant(ctx context.Context, input identityapp.BootstrapTenantInput) (domain.Tenant, domain.APIKey, string, error) {
	preparedIdentity, err := l.identityCommands.PrepareTenantBootstrap(ctx, input)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", fromIdentityContextError(err)
	}
	preparedSigning, err := l.verificationCommands.PrepareInitialSigningKey(ctx, preparedIdentity.Tenant.ID)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", fromVerificationContextError(err)
	}
	defer clear(preparedSigning.PrivateMaterial)

	if err := l.executeTenantBootstrap(ctx, preparedIdentity, preparedSigning); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", bootstrapContextError(err)
	}
	tenant, key, secret := preparedIdentity.PublicResult()
	return tenantFromIdentityContext(tenant), apiKeyFromIdentityContext(key), secret, nil
}

func (l *Ledger) executeTenantBootstrap(ctx context.Context, identity identityapp.PreparedTenantBootstrap, signing verificationapp.PreparedSigningKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	identityTx := newLedgerIdentityTransaction(l)
	verificationTx := newLedgerVerificationTransaction(l)
	command := func(ctx context.Context) error {
		if err := l.identityCommands.CommitTenantBootstrap(ctx, identityTx, identity); err != nil {
			return err
		}
		return l.verificationCommands.CommitInitialSigningKey(ctx, verificationTx.Verification(), identity.Tenant.ID, signing)
	}

	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			identityTx.repositories = &repositories
			verificationTx.repositories = &repositories
			return command(ctx)
		})
		if err != nil {
			return err
		}
		identityTx.publish()
		verificationTx.publish()
		return nil
	}
	if err := command(ctx); err != nil {
		return err
	}
	return l.commitTenantBootstrapCompatibility(ctx, identityTx, verificationTx)
}

func (l *Ledger) commitTenantBootstrapCompatibility(ctx context.Context, identityTx *ledgerIdentityTransaction, verificationTx *ledgerVerificationTransaction) error {
	tenants := cloneTenantMap(l.tenants)
	apiKeys := cloneAPIKeyMap(l.apiKeys)
	signingKeys := cloneSigningKeyMap(l.signingKeys)
	chain := cloneAuditChainMap(l.chain)
	identityTx.publish()
	verificationTx.publish()
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		l.tenants = tenants
		l.apiKeys = apiKeys
		l.signingKeys = signingKeys
		l.chain = chain
		return err
	}
	return nil
}

func bootstrapContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, identityapp.ErrValidation), errors.Is(err, verificationapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, identityapp.ErrForbidden), errors.Is(err, verificationapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, identityapp.ErrNotFound), errors.Is(err, verificationapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, identityapp.ErrConflict), errors.Is(err, verificationapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
