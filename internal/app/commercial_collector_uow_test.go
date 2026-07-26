package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingCommercialCollectorRepository struct{ EnterpriseRepository }

func (failingCommercialCollectorRepository) InsertCommercialCollectorDefinition(context.Context, domain.CommercialCollectorDefinition) error {
	return errInjectedRepositoryFailure
}

func TestCommercialCollectorUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	collector, err := ledger.CreateCommercialCollectorDefinition(ctx, actor, CreateCommercialCollectorInput{Name: "Scanner", Provider: "scannerco", Version: "1.0.0", ManifestHash: sampleDigest("commercial"), AllowedScopes: []string{ScopeEvidenceWrite}})
	if err != nil {
		t.Fatalf("create commercial collector: %v", err)
	}
	if ledger.commercialCollectors[collector.ID].ID != collector.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("commercial collector was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Enterprise = failingCommercialCollectorRepository{EnterpriseRepository: repositories.Enterprise}
		return repositories
	}}
	beforeCollectors, beforeChain := len(ledger.commercialCollectors), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateCommercialCollectorDefinition(ctx, actor, CreateCommercialCollectorInput{Name: "Other scanner", Provider: "scannerco", Version: "1.0.0", ManifestHash: sampleDigest("other-commercial"), AllowedScopes: []string{ScopeEvidenceWrite}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed commercial collector err=%v, want injected repository failure", err)
	}
	if len(ledger.commercialCollectors) != beforeCollectors || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed commercial collector published cached state")
	}
}
