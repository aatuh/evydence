package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingAnomalyReportRepository struct{ FutureExtensionsRepository }

func (failingAnomalyReportRepository) InsertAnomalyReport(context.Context, domain.AnomalyReport) error {
	return errInjectedRepositoryFailure
}

func TestAnomalyReportUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	report, err := ledger.GenerateAnomalyReport(ctx, actor, AnomalyReportInput{SubjectType: "release", SubjectID: release.ID})
	if err != nil {
		t.Fatalf("generate anomaly report: %v", err)
	}
	if ledger.anomalyReports[report.ID].ID != report.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("anomaly report was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingAnomalyReportRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeReports, beforeChain := len(ledger.anomalyReports), len(ledger.chain[actor.TenantID])
	if _, err := ledger.GenerateAnomalyReport(ctx, actor, AnomalyReportInput{SubjectType: "release", SubjectID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed anomaly report err=%v, want injected repository failure", err)
	}
	if len(ledger.anomalyReports) != beforeReports || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed anomaly report published cached state")
	}
}
