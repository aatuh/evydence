package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingGraphSnapshotRepository struct{ FutureExtensionsRepository }

func (failingGraphSnapshotRepository) InsertEvidenceGraphSnapshot(context.Context, domain.EvidenceGraphSnapshot) error {
	return errInjectedRepositoryFailure
}

func TestGraphSnapshotUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Graph", "graph")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	graph, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: product.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("create graph snapshot: %v", err)
	}
	if _, ok := ledger.graphSnapshots[graph.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("graph snapshot was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingGraphSnapshotRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeGraphs, beforeChain := len(ledger.graphSnapshots), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: product.ID, ReleaseID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed graph snapshot err=%v, want injected repository failure", err)
	}
	if len(ledger.graphSnapshots) != beforeGraphs || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed graph snapshot published cached state")
	}
}
