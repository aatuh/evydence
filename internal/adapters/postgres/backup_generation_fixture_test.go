package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Recovery setup uses the actual v2 command and PostgreSQL's complete current
// commitment/audit readers. It does not reconstruct or publish Ledger state.
func generateBackupManifestFixture(ctx context.Context, factory app.UnitOfWorkFactory, actor domain.Actor) (domain.BackupManifest, error) {
	commands, err := newBackupGenerationFixture(factory)
	if err != nil {
		return domain.BackupManifest{}, err
	}
	manifest, err := commands.GenerateBackupManifest(ctx, actor)
	if err != nil {
		return domain.BackupManifest{}, err
	}
	return domain.BackupManifestFromContextModel(manifest), nil
}

func newBackupGenerationFixture(factory app.UnitOfWorkFactory) (*verificationapp.BackupGenerationCommands, error) {
	if factory == nil {
		return nil, verificationapp.ErrValidation
	}
	return verificationapp.NewBackupGenerationCommands(verificationapp.BackupGenerationConfig{Transactions: postgresBackupGenerationTransactions{factory}, Authorizer: verificationquery.NewRetentionAuthorizer(), Hasher: postgresCustomerFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type postgresBackupGenerationTransactions struct{ factory app.UnitOfWorkFactory }
type postgresBackupGenerationTransaction struct {
	state     verificationapp.BackupStateCommitmentReader
	chain     verificationapp.AuditChainVerificationReader
	integrity app.IntegrityRepository
	audit     app.AuditRepository
	guard     postgresBundleFence
}

func (f postgresBackupGenerationTransactions) ExecuteBackupGeneration(ctx context.Context, run func(context.Context, verificationapp.BackupGenerationTransaction) error) error {
	return postgresBackupGenerationError(app.ExecuteUnitOfWork(ctx, f.factory, func(ctx context.Context, r app.Repositories) error {
		state, complete := r.Integrity.(verificationapp.BackupStateCommitmentReader)
		chain, verified := r.Verification.(verificationapp.AuditChainVerificationReader)
		guard, guarded := r.Identity.(postgresBundleFence)
		if !complete || !verified || !guarded || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresBackupGenerationTransaction{state, chain, r.Integrity, r.Audit, guard})
	}))
}

func (t postgresBackupGenerationTransaction) ReadBackupStateCommitment(ctx context.Context, tenant string) (verificationapp.BackupStateCommitment, error) {
	v, err := t.state.ReadBackupStateCommitment(ctx, tenant)
	return v, postgresBackupGenerationError(err)
}
func (t postgresBackupGenerationTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	v, err := t.chain.LockAuditChainVerification(ctx, tenant)
	return v, postgresBackupGenerationError(err)
}
func (t postgresBackupGenerationTransaction) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	v, err := t.chain.ReadAuditChainVerificationPage(ctx, view, after, budget)
	return v, postgresBackupGenerationError(err)
}
func (t postgresBackupGenerationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := verificationquery.NewRetentionAuthorizer().Authorize(ctx, actor, request); err != nil {
		return err
	}
	return postgresBackupGenerationError(t.guard.LockAPIKeyCreation(ctx, actor.TenantID))
}
func (t postgresBackupGenerationTransaction) InsertBackupManifest(ctx context.Context, manifest verificationdomain.BackupManifest) error {
	return postgresBackupGenerationError(t.integrity.InsertBackupManifest(ctx, domain.BackupManifestFromContextModel(manifest)))
}
func (t postgresBackupGenerationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (postgresCustomerFixtureTransaction{audit: t.audit}).AppendAudit(ctx, event)
	return v, postgresBackupGenerationError(err)
}

func postgresBackupGenerationError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return verificationapp.ErrNotFound
	case errors.Is(err, app.ErrForbidden):
		return verificationapp.ErrForbidden
	case errors.Is(err, app.ErrConflict):
		return verificationapp.ErrConflict
	default:
		return err
	}
}
