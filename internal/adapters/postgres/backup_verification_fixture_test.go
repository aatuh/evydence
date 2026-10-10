package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Recovery fixtures verify restored recorded facts through the focused native
// reader/transaction, without reconstructing a Ledger for this assessment.
func verifyBackupManifestFixture(ctx context.Context, store *Store, actor domain.Actor, id string) (domain.VerificationResult, error) {
	c, err := verificationapp.NewBackupVerificationCommands(verificationapp.BackupVerificationConfig{Transactions: postgresBackupVerificationFixture{store}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.VerificationResult{}, err
	}
	v, err := c.VerifyBackupManifest(ctx, actor, id)
	return domain.VerificationResultFromContextModel(v), err
}

type postgresBackupVerificationFixture struct{ store *Store }
type postgresBackupVerificationTransaction struct {
	reader       verificationapp.BackupVerificationReader
	verification app.VerificationRepository
	audit        app.AuditRepository
	outbox       app.OutboxRepository
}

func (f postgresBackupVerificationFixture) ExecuteBackupVerification(ctx context.Context, run func(context.Context, verificationapp.BackupVerificationTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.BackupVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresBackupVerificationTransaction{reader, r.Verification, r.Audit, r.Outbox})
	})
}
func (t postgresBackupVerificationTransaction) ReadBackupVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	return t.reader.ReadBackupVerification(ctx, s)
}
func (t postgresBackupVerificationTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t postgresBackupVerificationTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.verification.InsertVerificationResult(ctx, domain.VerificationResultFromContextModel(v))
}
func (t postgresBackupVerificationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (postgresCustomerFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
}
func (t postgresBackupVerificationTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return (postgresBundleTransaction{outbox: t.outbox}).EnqueueOutbox(ctx, e)
}
