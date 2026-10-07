package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Existing local HTTP fixtures retain their real guard, redaction, signing and
// isolated replay behavior. Runtime Package ports never accept these adapters.
type packageFixtureCommands struct{ catalogFixtureCommands }

func (f packageFixtureCommands) AuthorizeReportTemplateCreation(ctx context.Context, actor domain.Actor, input packageapp.CreateReportTemplateInput) error {
	return f.commandLedger(ctx).AuthorizeReportTemplateCreation(ctx, actor, input)
}
func (f packageFixtureCommands) AuthorizeReportRendering(ctx context.Context, actor domain.Actor, input packageapp.RenderReportInput) error {
	return f.commandLedger(ctx).AuthorizeReportRendering(ctx, actor, input)
}
func (f packageFixtureCommands) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, input packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	value, err := f.commandLedger(ctx).CreateCustomReportTemplate(ctx, actor, app.CreateReportTemplateInput{Name: input.Name, Version: input.Version, ReportType: input.ReportType, AllowedFields: input.AllowedFields, Template: input.Template})
	return packagedomain.CustomReportTemplate(value), err
}
func (f packageFixtureCommands) RenderCustomReport(ctx context.Context, actor domain.Actor, input packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	value, err := f.commandLedger(ctx).RenderCustomReport(ctx, actor, app.RenderReportInput{TemplateID: input.TemplateID, SubjectType: input.SubjectType, SubjectID: input.SubjectID})
	return packagedomain.RenderedCustomReport(value), err
}
func (f packageFixtureCommands) AuthorizeBundleImport(ctx context.Context, actor domain.Actor, bundle packagedomain.EvidenceBundle) error {
	return f.commandLedger(ctx).AuthorizeBundleImport(ctx, actor, bundle)
}
func (f packageFixtureCommands) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	value, err := f.commandLedger(ctx).ImportEvidenceBundle(ctx, actor, evidenceBundleFromCommands(bundle))
	return packagedomain.EvidenceBundleImport(value), err
}
func (f packageFixtureCommands) AuthorizeEvidenceBundleExport(ctx context.Context, actor domain.Actor, release string, ids []string) error {
	return f.commandLedger(ctx).AuthorizeEvidenceBundleExport(ctx, actor, release, ids)
}
func (f packageFixtureCommands) AuthorizeEvidenceBundleReplay(ctx context.Context, actor domain.Actor, release string, ids []string) error {
	return f.commandLedger(ctx).AuthorizeEvidenceBundleExport(ctx, actor, release, ids)
}
func (f packageFixtureCommands) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, release string, ids []string) (packagedomain.EvidenceBundle, error) {
	value, err := f.commandLedger(ctx).ExportEvidenceBundle(ctx, actor, release, ids)
	return evidenceBundleForImport(value), err
}

func (s *Server) bindPackageFixturePorts(ledger *app.Ledger) {
	commands := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.reportTemplateCommands.(packageFixtureCommands); s.reportTemplateCommands == nil || fixture {
		s.reportTemplateCommands = commands
	}
	if _, fixture := s.bundleImportCommand.(packageFixtureCommands); s.bundleImportCommand == nil || fixture {
		s.bundleImportCommand = commands
	}
	if _, fixture := s.evidenceBundleCommands.(packageFixtureCommands); s.evidenceBundleCommands == nil || fixture {
		s.evidenceBundleCommands = commands
	}
}

var (
	_ ReportTemplateCommands = packageFixtureCommands{}
	_ BundleImportCommand    = packageFixtureCommands{}
	_ EvidenceBundleCommands = packageFixtureCommands{}
)
