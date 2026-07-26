package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingPDFReportRepository struct{ FutureExtensionsRepository }

func (failingPDFReportRepository) InsertPDFReportPackage(context.Context, domain.PDFReportPackage) error {
	return errInjectedRepositoryFailure
}

func TestPDFReportPackageUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
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
	report, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: product.ID, ReleaseID: release.ID, Title: "Readiness"})
	if err != nil {
		t.Fatalf("create PDF report package: %v", err)
	}
	if _, ok := ledger.pdfReports[report.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("PDF report package was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingPDFReportRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeReports, beforeChain := len(ledger.pdfReports), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: product.ID, ReleaseID: release.ID, Title: "Failed report"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed PDF report package err=%v, want injected repository failure", err)
	}
	if len(ledger.pdfReports) != beforeReports || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed PDF report package published cached state")
	}
}
