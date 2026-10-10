package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type backupVerificationFixtureReader interface {
	verificationapp.BackupVerificationReader
	LockBackupVerificationScope(context.Context, string, string) error
}
type backupVerificationFixtureTransactions struct{ catalogFixtureCommands }
type backupVerificationFixtureTransaction struct {
	reader  backupVerificationFixtureReader
	receipt releaseBundleVerificationFixtureTransaction
}

// Recorded facts and receipt effects share the current typed fixture view.
// No aggregate manifest map, present-day backup export or restore is consulted.
func (f backupVerificationFixtureTransactions) ExecuteBackupVerification(ctx context.Context, run func(context.Context, verificationapp.BackupVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(backupVerificationFixtureReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, backupVerificationFixtureTransaction{reader, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (t backupVerificationFixtureTransaction) ReadBackupVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	v, err := t.reader.ReadBackupVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t backupVerificationFixtureTransaction) LockBackupVerificationScope(ctx context.Context, tenant, id string) error {
	return signingFixtureError(t.reader.LockBackupVerificationScope(ctx, tenant, id))
}
func (t backupVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t backupVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t backupVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t backupVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (f verificationCommandFixture) verifyCurrentBackup(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewBackupVerificationCommands(verificationapp.BackupVerificationConfig{Transactions: backupVerificationFixtureTransactions(f), Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyBackupManifest(ctx, a, id)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) authorizeCurrentBackup(ctx context.Context, a domain.Actor, id string) error {
	policy := verificationquery.NewEvidenceVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	_, id, err := verificationapp.NormalizeSubjectVerificationInput("backup_manifest", id)
	if err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError(backupVerificationFixtureTransactions(f).ExecuteBackupVerification(ctx, func(ctx context.Context, tx verificationapp.BackupVerificationTransaction) error {
		locker, ok := tx.(interface {
			LockBackupVerificationScope(context.Context, string, string) error
		})
		if !ok {
			return verificationapp.ErrValidation
		}
		if err := locker.LockBackupVerificationScope(ctx, a.TenantID, id); err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, TenantWide: true})
	}))
}
