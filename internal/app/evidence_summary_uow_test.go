package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingEvidenceSummaryRepository struct{ FutureExtensionsRepository }

func (failingEvidenceSummaryRepository) InsertEvidenceSummary(context.Context, domain.EvidenceSummary) error {
	return errInjectedRepositoryFailure
}

func TestEvidenceSummaryUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Summary", "summary")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "build", Title: "Summary build", PayloadHash: sampleDigest("summary-build")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	summary, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}})
	if err != nil {
		t.Fatalf("create evidence summary: %v", err)
	}
	if _, ok := ledger.evidenceSummaries[summary.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("evidence summary was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingEvidenceSummaryRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeSummaries, beforeChain := len(ledger.evidenceSummaries), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed evidence summary err=%v, want injected repository failure", err)
	}
	if len(ledger.evidenceSummaries) != beforeSummaries || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed evidence summary published cached state")
	}
}
