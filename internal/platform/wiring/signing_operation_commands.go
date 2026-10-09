package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildSigningOperationCommands(factory app.UnitOfWorkFactory, executor app.SigningExecutor) (*verificationapp.SigningOperationCommands, error) {
	if factory == nil {
		return nil, errors.New("signing operation transactions are required")
	}
	var signer verificationapp.ProviderSigningExecutor
	if executor != nil {
		signer = providerSigningExecutor{executor}
	}
	return verificationapp.NewSigningOperationCommands(verificationapp.SigningOperationConfig{Transactions: signingOperationTransactions{factory}, Signer: signer, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type providerSigningExecutor struct{ client app.SigningExecutor }

func (s providerSigningExecutor) SignOperation(ctx context.Context, r verificationapp.ProviderSigningRequest) (verificationapp.ProviderSigningResult, error) {
	v, err := s.client.Sign(ctx, app.SigningRequestFromVerification(r))
	if err != nil {
		return verificationapp.ProviderSigningResult{}, mapSigningOperationWriteError(err)
	}
	out := app.SigningResultToVerification(v)
	// Validate original bounds and bindings before sanitizing provider diagnostics.
	if err := verificationapp.ValidateProviderSigningResult(r, out); err != nil {
		return verificationapp.ProviderSigningResult{}, err
	}
	return app.SigningResultToVerification(app.SanitizeSigningResultMetadata(v)), nil
}

type signingOperationRepository interface {
	verificationapp.SigningOperationReader
	InsertFocusedSigningOperation(context.Context, verificationdomain.Signature, verificationdomain.SigningOperation) error
}
type signingOperationTransactions struct{ factory app.UnitOfWorkFactory }

func (t signingOperationTransactions) ExecuteSigningOperation(ctx context.Context, tenant string, fn func(context.Context, verificationapp.SigningOperationTransaction) error) error {
	return mapSigningOperationWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(signingOperationRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, signingOperationTransaction{r, repos.Audit})
	}))
}

type signingOperationTransaction struct {
	signingOperationRepository
	audit app.AuditRepository
}

func (t signingOperationTransaction) ReadSigningOperationProvider(ctx context.Context, tenant, id string) (verificationapp.SigningOperationProvider, error) {
	v, err := t.signingOperationRepository.ReadSigningOperationProvider(ctx, tenant, id)
	return v, mapSigningOperationWriteError(err)
}
func (t signingOperationTransaction) ReadSigningOperationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SigningOperationScope, error) {
	v, err := t.signingOperationRepository.ReadSigningOperationScope(ctx, tenant, kind, id)
	return v, mapSigningOperationWriteError(err)
}
func (t signingOperationTransaction) InsertFocusedSigningOperation(ctx context.Context, s verificationdomain.Signature, v verificationdomain.SigningOperation) error {
	return mapSigningOperationWriteError(t.signingOperationRepository.InsertFocusedSigningOperation(ctx, s, v))
}
func (t signingOperationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, a, r)
}
func (t signingOperationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapSigningOperationWriteError(err)
}
func mapSigningOperationWriteError(err error) error {
	if errors.Is(err, app.ErrVerificationFailed) {
		return verificationapp.ErrVerificationFailed
	}
	return mapSigningKeyWriteError(err)
}
