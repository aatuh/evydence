package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingCustomPolicyRepository struct{ RiskRepository }

func (failingCustomPolicyRepository) InsertCustomPolicy(context.Context, domain.CustomPolicy) error {
	return errInjectedRepositoryFailure
}

func (failingCustomPolicyRepository) InsertCustomPolicyEvaluation(context.Context, domain.CustomPolicyEvaluation) error {
	return errInjectedRepositoryFailure
}

func TestCustomPolicyWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Policy", "policy")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	auditEntriesBefore := len(ledger.chain[actor.TenantID])
	policy, err := ledger.CreateCustomPolicy(ctx, actor, CreateCustomPolicyInput{Name: "Release evidence", Version: "1", Rules: []domain.PolicyRule{{Name: "SBOM", EvidenceType: "sbom", Severity: "high", Required: true}}})
	if err != nil {
		t.Fatalf("create custom policy: %v", err)
	}
	evaluation, err := ledger.EvaluateCustomPolicy(ctx, actor, policy.ID, release.ID)
	if err != nil {
		t.Fatalf("evaluate custom policy: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after custom policy writes: %v", err)
	}
	if snapshot.CustomPolicies[policy.ID].ID != policy.ID || snapshot.CustomPolicyEvaluations[evaluation.ID].ID != evaluation.ID || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+2 {
		t.Fatalf("custom policy writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Risk = failingCustomPolicyRepository{RiskRepository: repositories.Risk}
		return repositories
	}}
	beforePolicies, beforeEvals, beforeAudit := len(ledger.customPolicies), len(ledger.customPolicyEvals), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateCustomPolicy(ctx, actor, CreateCustomPolicyInput{Name: "Failed", Version: "1", Rules: []domain.PolicyRule{{Name: "SBOM", EvidenceType: "sbom", Severity: "high", Required: true}}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed custom policy create err=%v, want injected repository failure", err)
	}
	if _, err := ledger.EvaluateCustomPolicy(ctx, actor, policy.ID, release.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed custom policy evaluation err=%v, want injected repository failure", err)
	}
	if len(ledger.customPolicies) != beforePolicies || len(ledger.customPolicyEvals) != beforeEvals || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed custom policy write published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed custom policy writes: %v", err)
	}
	if len(after.CustomPolicies) != len(snapshot.CustomPolicies) || len(after.CustomPolicyEvaluations) != len(snapshot.CustomPolicyEvaluations) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed custom policy write published durable state: before=%#v after=%#v", snapshot, after)
	}
}
