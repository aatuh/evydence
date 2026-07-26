package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingMarketplaceCollectorRepository struct{ FutureExtensionsRepository }

func (failingMarketplaceCollectorRepository) InsertMarketplaceCollector(context.Context, domain.MarketplaceCollector) error {
	return errInjectedRepositoryFailure
}

func TestMarketplaceCollectorUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	collector, err := ledger.CreateMarketplaceCollector(ctx, actor, CreateMarketplaceCollectorInput{Name: "collector", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: sampleDigest("collector")})
	if err != nil {
		t.Fatalf("create marketplace collector: %v", err)
	}
	if _, ok := ledger.marketplaceCollectors[collector.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("marketplace collector was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingMarketplaceCollectorRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeCollectors, beforeChain := len(ledger.marketplaceCollectors), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateMarketplaceCollector(ctx, actor, CreateMarketplaceCollectorInput{Name: "failed", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: sampleDigest("failed")}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed marketplace collector err=%v, want injected repository failure", err)
	}
	if len(ledger.marketplaceCollectors) != beforeCollectors || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed marketplace collector published cached state")
	}
}
