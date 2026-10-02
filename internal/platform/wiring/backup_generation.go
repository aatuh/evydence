package wiring

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

func BuildBackupGenerationCommands(factory app.UnitOfWorkFactory) (*verificationapp.BackupGenerationCommands, error) {
	if factory == nil {
		return nil, errors.New("backup generation transactions are required")
	}
	return verificationapp.NewBackupGenerationCommands(verificationapp.BackupGenerationConfig{Transactions: backupGenerationTransactions{factory}, Authorizer: verificationquery.NewRetentionAuthorizer(), Hasher: verificationCanonicalHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type backupGenerationTransactions struct{ factory app.UnitOfWorkFactory }

func (t backupGenerationTransactions) ExecuteBackupGeneration(ctx context.Context, fn func(context.Context, verificationapp.BackupGenerationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		state, ok := repos.Integrity.(verificationapp.BackupStateCommitmentReader)
		chain, valid := repos.Verification.(verificationapp.AuditChainVerificationReader)
		if !ok || !valid || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, backupGenerationTransaction{state, chain, repos.Integrity, repos.Audit})
	}))
}

type backupGenerationTransaction struct {
	state     verificationapp.BackupStateCommitmentReader
	chain     verificationapp.AuditChainVerificationReader
	integrity app.IntegrityRepository
	audit     app.AuditRepository
}

func (t backupGenerationTransaction) ReadBackupStateCommitment(ctx context.Context, tenant string) (verificationapp.BackupStateCommitment, error) {
	v, err := t.state.ReadBackupStateCommitment(ctx, tenant)
	return v, mapSigningKeyWriteError(err)
}
func (t backupGenerationTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	v, err := t.chain.LockAuditChainVerification(ctx, tenant)
	return v, mapSigningKeyWriteError(err)
}
func (t backupGenerationTransaction) ReadAuditChainVerificationPage(ctx context.Context, v verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	p, err := t.chain.ReadAuditChainVerificationPage(ctx, v, after, budget)
	return p, mapSigningKeyWriteError(err)
}
func (t backupGenerationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewRetentionAuthorizer().Authorize(ctx, a, r)
}
func (t backupGenerationTransaction) InsertBackupManifest(ctx context.Context, m verificationdomain.BackupManifest) error {
	return mapSigningKeyWriteError(t.integrity.InsertBackupManifest(ctx, domain.BackupManifestFromContextModel(m)))
}
func (t backupGenerationTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, a)
	return r, mapSigningKeyWriteError(err)
}
