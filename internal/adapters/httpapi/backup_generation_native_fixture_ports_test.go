package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// This is an explicit commitment-port test double, NOT a memory implementation
// of the 98-resource PostgreSQL profile. Only audit inspection, authority,
// manifest/audit writes and replay composition are real in these HTTP tests.
// Complete state hashing remains a PostgreSQL integration-test responsibility.
type backupGenerationContractCommitment func(context.Context, string, verificationapp.AuditChainVerificationReader) (verificationapp.BackupStateCommitment, error)

type backupGenerationFixtureTransactions struct {
	catalogFixtureCommands
	commitment backupGenerationContractCommitment
}
type backupGenerationFixtureTransaction struct {
	commitment backupGenerationContractCommitment
	chain      verificationapp.AuditChainVerificationReader
	integrity  app.IntegrityRepository
	audit      app.AuditRepository
	guard      releaseBundleFixtureFence
}

func (f backupGenerationFixtureTransactions) ExecuteBackupGeneration(ctx context.Context, run func(context.Context, verificationapp.BackupGenerationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil || f.commitment == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		chain, verified := r.Verification.(verificationapp.AuditChainVerificationReader)
		guard, guarded := r.Identity.(releaseBundleFixtureFence)
		if !verified || !guarded || r.Integrity == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, backupGenerationFixtureTransaction{f.commitment, chain, r.Integrity, r.Audit, guard})
	}))
}
func (t backupGenerationFixtureTransaction) ReadBackupStateCommitment(ctx context.Context, tenant string) (verificationapp.BackupStateCommitment, error) {
	v, err := t.commitment(ctx, tenant, t.chain)
	return v, signingAdminFixtureError(err)
}
func (t backupGenerationFixtureTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	v, err := t.chain.LockAuditChainVerification(ctx, tenant)
	return v, signingAdminFixtureError(err)
}
func (t backupGenerationFixtureTransaction) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	v, err := t.chain.ReadAuditChainVerificationPage(ctx, view, after, budget)
	return v, signingAdminFixtureError(err)
}
func (t backupGenerationFixtureTransaction) Authorize(ctx context.Context, actor domain.Actor, request application.AuthorizationRequest) error {
	if err := verificationquery.NewBackupGenerationAuthorizer().Authorize(ctx, actor, request); err != nil {
		return err
	}
	return signingAdminFixtureError(t.guard.LockAPIKeyCreation(ctx, actor.TenantID))
}
func (t backupGenerationFixtureTransaction) InsertBackupManifest(ctx context.Context, manifest verificationdomain.BackupManifest) error {
	return signingAdminFixtureError(t.integrity.InsertBackupManifest(ctx, domain.BackupManifestFromContextModel(manifest)))
}
func (t backupGenerationFixtureTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, event)
}

func scriptedHTTPBackupCommitment(ctx context.Context, tenant string, chain verificationapp.AuditChainVerificationReader) (verificationapp.BackupStateCommitment, error) {
	view, err := chain.LockAuditChainVerification(ctx, tenant)
	if err != nil {
		return verificationapp.BackupStateCommitment{}, err
	}
	// A fixed synthetic digest makes it impossible to mistake this for a digest
	// computed from any subset of memory rows. The audit coordinate is current
	// so the real core still detects inconsistent commitments/audit views.
	hash, err := application.NormalizedJSONHash("HTTP backup commitment port test double; not a state snapshot")
	if err != nil {
		return verificationapp.BackupStateCommitment{}, err
	}
	counts := map[string]int{"audit_chain_entries": int(view.EntryCount), "artifact_signatures": 0, "cosign_verifications": 0, "evidence": 0, "merkle_batches": 0, "object_retention_policies": 0, "release_bundles": 0, "transparency_checkpoints": 0}
	return verificationapp.BackupStateCommitment{TenantID: tenant, Profile: verificationapp.BackupStateCommitmentProfile, StateHash: hash, ResourceCounts: counts, RowsRead: int(view.EntryCount) + 1, BytesRead: 64}, nil
}

func (f verificationCommandFixture) nativeBackupGeneration() (*verificationapp.BackupGenerationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	commitment := f.backupCommitment
	if commitment == nil {
		commitment = scriptedHTTPBackupCommitment
	}
	return verificationapp.NewBackupGenerationCommands(verificationapp.BackupGenerationConfig{Transactions: backupGenerationFixtureTransactions{f.catalogFixtureCommands, commitment}, Authorizer: verificationquery.NewBackupGenerationAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
}
