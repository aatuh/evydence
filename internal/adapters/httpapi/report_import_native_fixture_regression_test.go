package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestReportImportNativeFixturesUseCurrentRepositoriesWithoutAggregateStateOrClock(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	seed := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := packageapp.CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "subject_type", "generated_at", "private_field"}, Template: "{{inert-private-template-marker}}"}
	template, err := seed.CreateCustomReportTemplate(t.Context(), owner.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("report/import used aggregate clock") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	render := packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: " release ", SubjectID: " nonexistent-label "}
	bundle, err := decodeBundleImport([]byte(bundleImportNativeBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	portable := evidenceBundleForImport(bundle)
	portable.TenantID, portable.ReleaseID = "foreign-source-label", "foreign-release-label"
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeReportRendering(t.Context(), owner.actor, render); err != nil {
		t.Fatal("render guard used missing aggregate template cache", err)
	}
	if err := f.AuthorizeReportTemplateCreation(t.Context(), owner.actor, in); err != nil {
		t.Fatal("creation guard used aggregate tenant cache", err)
	}
	if err := f.AuthorizeBundleImport(t.Context(), owner.actor, portable); err != nil {
		t.Fatal("import guard used aggregate tenant cache", err)
	}
	afterGuards, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, afterGuards) {
		t.Fatal("report/import guards wrote effects", err)
	}
	report, err := f.RenderCustomReport(t.Context(), owner.actor, render)
	if err != nil || report.TemplateID != template.ID || report.SubjectType != "release" || report.SubjectID != "nonexistent-label" || len(report.Output) != 3 || report.Output["subject_type"] != render.SubjectType || report.Output["subject_id"] != render.SubjectID || report.Output["generated_at"] == nil || report.Hash == "" {
		t.Fatal("focused metadata report contract changed", report, err)
	}
	hash, err := application.NormalizedJSONHash(report.Output)
	if err != nil || report.Hash != hash || report.Output["generated_at"] != report.CreatedAt.Format(time.RFC3339) || report.SchemaVersion != "rendered-report.v1.0.0" {
		t.Fatal("report hash, timestamp or schema contract changed", err)
	}
	report.Output["subject_id"] = "caller mutation"
	in.Version = "2"
	created, err := f.CreateCustomReportTemplate(t.Context(), owner.actor, in)
	if err != nil || created.Name != in.Name || created.Version != "2" || created.Template != in.Template {
		t.Fatal("focused template creation failed", err)
	}
	created.AllowedFields[0] = "caller mutation"
	receipt, err := f.ImportEvidenceBundle(t.Context(), owner.actor, portable)
	if err != nil || receipt.TenantID != owner.actor.TenantID || receipt.BundleHash != portable.ManifestHash || receipt.Result != "accepted" || receipt.ImportedCount != 0 {
		t.Fatal("source labels changed local import receipt", receipt, err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.ReportTemplates) != len(before.ReportTemplates)+1 || len(after.RenderedReports) != len(before.RenderedReports)+1 || len(after.BundleImports) != len(before.BundleImports)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+3 || len(after.OutboxJobs) != len(before.OutboxJobs) || len(after.Signatures) != len(before.Signatures) || len(after.Evidence) != len(before.Evidence) {
		t.Fatal("report/import effects escaped focused transaction", err)
	}
	if after.RenderedReports[report.ID].Output["subject_id"] != render.SubjectID || after.ReportTemplates[created.ID].AllowedFields[0] == "caller mutation" {
		t.Fatal("returned report or template aliases stored contents")
	}
	factory.fail = true
	in.Version = "failed-commit"
	if value, err := f.CreateCustomReportTemplate(t.Context(), owner.actor, in); err == nil || !reflect.DeepEqual(value, packagedomain.CustomReportTemplate{}) {
		t.Fatal("failed template commit returned data", err)
	}
	if value, err := f.RenderCustomReport(t.Context(), owner.actor, render); err == nil || !reflect.DeepEqual(value, packagedomain.RenderedCustomReport{}) {
		t.Fatal("failed report commit returned data", err)
	}
	if value, err := f.ImportEvidenceBundle(t.Context(), owner.actor, portable); err == nil || !reflect.DeepEqual(value, packagedomain.EvidenceBundleImport{}) {
		t.Fatal("failed import commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed report/import commits published effects", err)
	}
}

func TestReportImportNativeFixturesRejectRevokedScopeForeignTemplateAndCancellation(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	f := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := packageapp.CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}}
	template, err := f.CreateCustomReportTemplate(t.Context(), owner.actor, in)
	if err != nil {
		t.Fatal(err)
	}
	render := packageapp.RenderReportInput{TemplateID: template.ID, SubjectType: "label", SubjectID: "not-a-resource"}
	bundle, err := decodeBundleImport([]byte(bundleImportNativeBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	portable := evidenceBundleForImport(bundle)
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeReportRead, app.ScopeBundleWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{app.ScopeReportRead, app.ScopeBundleWrite}}}}
	if err := f.AuthorizeReportRendering(t.Context(), human, render); err != nil {
		t.Fatal("current tenant grant could not authorize rendering", err)
	}
	if err := f.AuthorizeReportTemplateCreation(t.Context(), human, in); err != nil {
		t.Fatal("current tenant grant could not authorize definition creation", err)
	}
	if err := f.AuthorizeBundleImport(t.Context(), human, portable); err != nil {
		t.Fatal("current tenant grant could not authorize import receipt", err)
	}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeReportRead, app.ScopeBundleWrite}}}
	for _, run := range []func(context.Context, domain.Actor) error{
		func(ctx context.Context, a domain.Actor) error { return f.AuthorizeReportTemplateCreation(ctx, a, in) },
		func(ctx context.Context, a domain.Actor) error { return f.AuthorizeReportRendering(ctx, a, render) },
		func(ctx context.Context, a domain.Actor) error { return f.AuthorizeBundleImport(ctx, a, portable) },
		func(ctx context.Context, a domain.Actor) error {
			_, err := f.CreateCustomReportTemplate(ctx, a, in)
			return err
		},
		func(ctx context.Context, a domain.Actor) error {
			_, err := f.RenderCustomReport(ctx, a, render)
			return err
		},
		func(ctx context.Context, a domain.Actor) error {
			_, err := f.ImportEvidenceBundle(ctx, a, portable)
			return err
		},
	} {
		if err := run(t.Context(), human); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("product grant granted tenant-wide report/import authority", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := run(ctx, owner.actor); !errors.Is(err, context.Canceled) {
			t.Fatal("report/import cancellation lost", err)
		}
	}
	if err := f.AuthorizeReportRendering(t.Context(), foreign.actor, render); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign template replay authorized", err)
	}
	if v, err := f.RenderCustomReport(t.Context(), foreign.actor, render); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, packagedomain.RenderedCustomReport{}) {
		t.Fatal("foreign template rendered", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied report/import changed durable state", err)
	}
}

func TestReportImportNativeFixturesRequireRepositoriesAndPreserveInjectedDependencies(t *testing.T) {
	first := newLegacyLedgerFixture(app.Config{APIKeyPepper: "first-fixture"})
	second := newLegacyLedgerFixture(app.Config{APIKeyPepper: "second-fixture"})
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{app.ScopeReportRead, app.ScopeBundleWrite}}
	f := packageFixtureCommands{catalogFixtureCommands{ledger: first}}
	in := packageapp.CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}}
	bundle, err := decodeBundleImport([]byte(bundleImportNativeBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeReportTemplateCreation(t.Context(), actor, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing template repositories fell back to aggregate state", err)
	}
	if v, err := f.CreateCustomReportTemplate(t.Context(), actor, in); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, packagedomain.CustomReportTemplate{}) {
		t.Fatal("missing template repositories returned data", err)
	}
	if err := f.AuthorizeBundleImport(t.Context(), actor, evidenceBundleForImport(bundle)); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing import repositories fell back to aggregate state", err)
	}
	if v, err := f.ImportEvidenceBundle(t.Context(), actor, evidenceBundleForImport(bundle)); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, packagedomain.EvidenceBundleImport{}) {
		t.Fatal("missing import repositories returned data", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := application.ClockFunc(func() time.Time { return now })
	server := &Server{
		reportTemplateCommands: reportTemplateFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: first}, clock: clock},
		bundleImportCommand:    bundleImportFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: first}, clock: clock},
	}
	server.bindPackageFixturePorts(second)
	reportFixture, ok := server.reportTemplateCommands.(reportTemplateFixtureCommands)
	if !ok || reportFixture.ledger != second || reportFixture.clock == nil || !reportFixture.clock.Now().Equal(now) {
		t.Fatal("report binding lost explicit fixture dependencies")
	}
	importFixture, ok := server.bundleImportCommand.(bundleImportFixtureCommands)
	if !ok || importFixture.ledger != second || importFixture.clock == nil || !importFixture.clock.Now().Equal(now) {
		t.Fatal("import binding lost explicit fixture dependencies")
	}
	injectedTemplate, injectedImport := &reportTemplateHTTPFake{}, &bundleImportHTTPFake{}
	server.reportTemplateCommands, server.bundleImportCommand = injectedTemplate, injectedImport
	server.bindPackageFixturePorts(first)
	if server.reportTemplateCommands != injectedTemplate || server.bundleImportCommand != injectedImport {
		t.Fatal("fixture binding replaced injected native report/import ports")
	}
}
