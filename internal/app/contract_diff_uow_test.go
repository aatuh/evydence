package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingContractDiffRepository struct{ RiskRepository }

func (failingContractDiffRepository) InsertContractDiff(context.Context, domain.ContractDiff) error {
	return errInjectedRepositoryFailure
}

func TestContractDiffUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Contract diff", "contract-diff")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	base, err := ledger.UploadOpenAPIContract(ctx, actor, product.ID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"Contract diff","version":"1"},"paths":{"/v1/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("upload base contract: %v", err)
	}
	target, err := ledger.UploadOpenAPIContract(ctx, actor, product.ID, release.ID, "v2", []byte(`{"openapi":"3.1.0","info":{"title":"Contract diff","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatalf("upload target contract: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	diff, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{BaseContractID: base.ID, TargetContractID: target.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("create contract diff: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after contract diff: %v", err)
	}
	if snapshot.ContractDiffs[diff.ID].ID != diff.ID || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 {
		t.Fatalf("contract diff was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Risk = failingContractDiffRepository{RiskRepository: repositories.Risk}
		return repositories
	}}
	beforeDiffs, beforeAudit := len(ledger.contractDiffs), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{BaseContractID: base.ID, TargetContractID: target.ID, ReleaseID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed contract diff err=%v, want injected repository failure", err)
	}
	if len(ledger.contractDiffs) != beforeDiffs || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed contract diff published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed contract diff: %v", err)
	}
	if len(after.ContractDiffs) != len(snapshot.ContractDiffs) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed contract diff published durable state: before=%#v after=%#v", snapshot, after)
	}
}
