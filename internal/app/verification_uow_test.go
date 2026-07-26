package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingVerificationRepository struct{ VerificationRepository }

func (failingVerificationRepository) InsertPolicyEvaluation(context.Context, domain.PolicyEvaluation) error {
	return errInjectedRepositoryFailure
}

func (failingVerificationRepository) InsertVerificationResult(context.Context, domain.VerificationResult) error {
	return errInjectedRepositoryFailure
}

func TestSubjectVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Subject verification", "subject-verification")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "build", Title: "Verified evidence", PayloadHash: sampleDigest("verified-evidence")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	result, err := ledger.VerifySubject(ctx, actor, "evidence_item", evidence.ID)
	if err != nil {
		t.Fatalf("verify subject: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after subject verification: %v", err)
	}
	if snapshot.VerificationResults[result.ID].ID != result.ID || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 || len(snapshot.OutboxJobs) != 1 {
		t.Fatalf("subject verification was not committed atomically: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Verification = failingVerificationRepository{VerificationRepository: repositories.Verification}
		return repositories
	}}
	beforeResults, beforeAudit := len(ledger.verifications), len(ledger.chain[actor.TenantID])
	if _, err := ledger.VerifySubject(ctx, actor, "evidence_item", evidence.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed subject verification err=%v, want injected repository failure", err)
	}
	if len(ledger.verifications) != beforeResults || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed subject verification published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed subject verification: %v", err)
	}
	if len(after.VerificationResults) != len(snapshot.VerificationResults) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) || len(after.OutboxJobs) != len(snapshot.OutboxJobs) {
		t.Fatalf("failed subject verification published durable state: before=%#v after=%#v", snapshot, after)
	}
}

func TestAuditChainVerificationUsesUnitOfWorkWithoutSubjectID(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	beforeAudit := len(ledger.chain[actor.TenantID])
	result, err := ledger.VerifySubject(ctx, actor, "audit_chain", "")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after audit-chain verification: %v", err)
	}
	if stored, ok := snapshot.VerificationResults[result.ID]; !ok || stored.SubjectType != "audit_chain" || stored.SubjectID != "" || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 || len(snapshot.OutboxJobs) != 1 {
		t.Fatalf("audit-chain verification was not committed atomically: %#v", snapshot)
	}
}

func TestPolicyEvaluationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Verification API", "verification-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evaluation, err := ledger.EvaluateRelease(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("evaluate release: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.PolicyEvaluations[evaluation.ID]; !ok || got.ReleaseID != release.ID || got.TenantID != actor.TenantID {
		t.Fatalf("policy evaluation not committed: %#v", snapshot.PolicyEvaluations)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Verification.InsertPolicyEvaluation(ctx, domain.PolicyEvaluation{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid policy evaluation err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Verification.InsertPolicyEvaluation(ctx, evaluation)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate policy evaluation err=%v, want conflict", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingRelease := evaluation
		missingRelease.ID = "policy_missing_release"
		missingRelease.ReleaseID = "release_missing"
		return repositories.Verification.InsertPolicyEvaluation(ctx, missingRelease)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("policy evaluation missing release err=%v, want not found", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Verification = failingVerificationRepository{VerificationRepository: repositories.Verification}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	beforePolicies := len(ledger.policies)
	if _, err := ledger.EvaluateRelease(ctx, actor, release.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed policy evaluation err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.PolicyEvaluations) != len(before.PolicyEvaluations) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.policies) != beforePolicies {
		t.Fatalf("failed policy evaluation published state: before=%#v after=%#v", before, after)
	}
}
