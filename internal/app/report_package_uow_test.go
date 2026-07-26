package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingReportPackageRepository struct{ PackageRepository }

func (failingReportPackageRepository) InsertHTMLReportPackage(context.Context, domain.HTMLReportPackage) error {
	return errInjectedRepositoryFailure
}

func (failingReportPackageRepository) InsertCustomReportTemplate(context.Context, domain.CustomReportTemplate) error {
	return errInjectedRepositoryFailure
}

func (failingReportPackageRepository) InsertRenderedCustomReport(context.Context, domain.RenderedCustomReport) error {
	return errInjectedRepositoryFailure
}

func TestReportPackageWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Reports", "reports")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	if _, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, "evydence-cra-readiness"); err != nil {
		t.Fatalf("install CRA readiness control pack: %v", err)
	}
	auditEntriesBefore := len(ledger.chain[actor.TenantID])
	htmlReport, err := ledger.CRAReadinessHTMLPackage(ctx, actor, product.ID, release.ID)
	if err != nil {
		t.Fatalf("create CRA HTML report: %v", err)
	}
	template, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "Release", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id"}, Template: "json"})
	if err != nil {
		t.Fatalf("create custom report template: %v", err)
	}
	rendered, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: release.ID})
	if err != nil {
		t.Fatalf("render custom report: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after report writes: %v", err)
	}
	if snapshot.HTMLReports[htmlReport.ID].ID != htmlReport.ID || snapshot.ReportTemplates[template.ID].ID != template.ID || snapshot.RenderedReports[rendered.ID].ID != rendered.ID || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+3 {
		t.Fatalf("report package writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Packages = failingReportPackageRepository{PackageRepository: repositories.Packages}
		return repositories
	}}
	beforeHTML, beforeTemplates, beforeRendered, beforeAudit := len(ledger.htmlReports), len(ledger.reportTemplates), len(ledger.renderedReports), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CRAReadinessHTMLPackage(ctx, actor, product.ID, release.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed CRA HTML report err=%v, want injected repository failure", err)
	}
	if _, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "Failed", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id"}}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed custom report template err=%v, want injected repository failure", err)
	}
	if _, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed rendered report err=%v, want injected repository failure", err)
	}
	if len(ledger.htmlReports) != beforeHTML || len(ledger.reportTemplates) != beforeTemplates || len(ledger.renderedReports) != beforeRendered || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed report package write published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed report writes: %v", err)
	}
	if len(after.HTMLReports) != len(snapshot.HTMLReports) || len(after.ReportTemplates) != len(snapshot.ReportTemplates) || len(after.RenderedReports) != len(snapshot.RenderedReports) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed report package write published durable state: before=%#v after=%#v", snapshot, after)
	}
}
