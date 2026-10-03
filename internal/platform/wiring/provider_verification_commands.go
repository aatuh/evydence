package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildProviderVerificationCommands(factory app.UnitOfWorkFactory, client app.ProviderIdentityValidator) (*identityapp.ProviderVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("provider verification transactions are required")
	}
	var live identityapp.ProviderIdentityValidator
	if client != nil {
		live = app.IdentityProviderAPIValidator{Client: client}
	}
	return identityapp.NewProviderVerificationCommands(identityapp.ProviderVerificationCommandConfig{Reader: providerReceiptReader{factory}, Transactions: providerReceiptTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Verifier: app.LocalSSOCredentialVerifier{}, LiveProvider: live, VerificationPolicy: app.LocalSSOVerificationPolicy{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type providerReceiptReader struct{ factory app.UnitOfWorkFactory }

func (r providerReceiptReader) read(ctx context.Context, tenant string, fn func(context.Context, identityapp.ProviderVerificationReader) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.ProviderVerificationReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence {
			return app.ErrValidation
		}
		// HTTP may supply the ambient idempotency transaction, so preflight
		// parent locks can survive until audit/commit. Take the existing
		// worker/audit fence and tenant lock first, as identity writes do.
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, reader)
	}))
}
func (r providerReceiptReader) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	var out identitydomain.SSOProvider
	err := r.read(ctx, tenant, func(ctx context.Context, reader identityapp.ProviderVerificationReader) error {
		var err error
		out, err = reader.ReadOwnedSSOProvider(ctx, tenant, id)
		return err
	})
	return out, err
}
func (r providerReceiptReader) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	var out identitydomain.UserIdentityLink
	var found bool
	err := r.read(ctx, tenant, func(ctx context.Context, reader identityapp.ProviderVerificationReader) error {
		var err error
		out, found, err = reader.IdentityLink(ctx, tenant, provider, subject)
		return err
	})
	return out, found, err
}

type providerReceiptTransactions struct{ factory app.UnitOfWorkFactory }
type providerReceiptTransaction struct{ exchange ssoExchangeTransaction }

func (t providerReceiptTransactions) ExecuteProviderVerification(ctx context.Context, fn func(context.Context, identityapp.ProviderVerificationTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		if repos.Identity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, providerReceiptTransaction{exchange: ssoExchangeTransaction{identity: repos.Identity, audit: repos.Audit}})
	}))
}
func (t providerReceiptTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t providerReceiptTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	return t.exchange.ValidateSSOExchangeState(ctx, s)
}
func (t providerReceiptTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return t.exchange.InsertProviderVerification(ctx, v)
}
func (t providerReceiptTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.exchange.AppendAudit(ctx, e)
}
