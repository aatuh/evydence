package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
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

func (f packageFixtureCommands) AuthorizeReleaseBundleCreation(ctx context.Context, actor domain.Actor, release string) error {
	return f.commandLedger(ctx).AuthorizeReleaseBundleCreation(ctx, actor, release)
}
func (f packageFixtureCommands) CreateReleaseBundle(ctx context.Context, actor domain.Actor, release string) (packagedomain.ReleaseBundle, error) {
	value, err := f.commandLedger(ctx).CreateReleaseBundle(ctx, actor, release)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return domain.ReleaseBundleToContextModel(value)
}

// Preserve the legacy preflight's real scoped policies. Fresh commands below
// resolve their actual fixture parents; runtime ports stabilize SQL ownership.
func (f packageFixtureCommands) AuthorizeCreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, input packageapp.CreateCustomerPackageInput) error {
	input, err := packageapp.NormalizeCustomerPackageInput(input)
	if err != nil {
		return err
	}
	return packagequery.NewCustomerPackageCreationAuthorizer().Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopePackageWrite, Resources: application.ResourceReferences{ProductID: input.ProductID, ReleaseID: input.ReleaseID}})
}
func (f packageFixtureCommands) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, input packageapp.CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	value, err := f.commandLedger(ctx).CreateCustomerSecurityPackage(ctx, actor, app.CreateCustomerPackageInput{ProductID: input.ProductID, ReleaseID: input.ReleaseID, RedactionProfileID: input.RedactionProfileID, Title: input.Title, ExpiresAt: input.ExpiresAt})
	return packagedomain.CustomerSecurityPackage(value), err
}
func (f packageFixtureCommands) AuthorizeCreateRedactionProfile(ctx context.Context, actor domain.Actor, input packageapp.CreateRedactionProfileInput) error {
	if _, err := packageapp.NormalizeRedactionProfileInput(input); err != nil {
		return err
	}
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopePackageWrite)
}
func (f packageFixtureCommands) CreateRedactionProfile(ctx context.Context, actor domain.Actor, input packageapp.CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	value, err := f.commandLedger(ctx).CreateRedactionProfile(ctx, actor, app.CreateRedactionProfileInput{Name: input.Name, Description: input.Description, Preset: input.Preset, AllowedTypes: input.AllowedTypes, ExcludedFields: input.ExcludedFields})
	return packagedomain.RedactionProfile(value), err
}
func (f packageFixtureCommands) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	value, err := f.commandLedger(ctx).AccessCustomerSecurityPackage(ctx, actor, id)
	return packagedomain.CustomerSecurityPackage(value), err
}
func (f packageFixtureCommands) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, id string) (packagedomain.SecurityReviewPackageReport, error) {
	value, err := f.commandLedger(ctx).SecurityReviewPackageReport(ctx, actor, id)
	return packagedomain.SecurityReviewPackageReport(value), err
}
func (f packageFixtureCommands) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, product, release string) (packagedomain.HTMLReportPackage, error) {
	value, err := f.commandLedger(ctx).CRAReadinessHTMLPackage(ctx, actor, product, release)
	return packagedomain.HTMLReportPackage(value), err
}

type packageReadinessFixtureQuery struct {
	catalogFixtureCommands
	clock func() time.Time
}

func (f packageReadinessFixtureQuery) Report(ctx context.Context, actor domain.Actor, release string) (packagedomain.ReleaseReadinessReport, error) {
	query, err := packagequery.NewReleaseReadinessReport(f, f.now)
	if err != nil {
		return packagedomain.ReleaseReadinessReport{}, err
	}
	return query.Report(ctx, actor, release)
}

func readinessFixtureReportModel(value domain.ReleaseReadinessReport) packagedomain.ReleaseReadinessReport {
	checks := make([]packagedomain.PolicyCheckSnapshot, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, packagedomain.PolicyCheckSnapshot(check))
	}
	sections := make([]packagedomain.ReadinessSection, 0, len(value.Sections))
	for _, section := range value.Sections {
		questions := make([]packagedomain.ReadinessQuestion, 0, len(section.Questions))
		for _, question := range section.Questions {
			questions = append(questions, packagedomain.ReadinessQuestion(question))
		}
		sections = append(sections, packagedomain.ReadinessSection{ID: section.ID, Title: section.Title, Status: section.Status, Summary: section.Summary, Questions: questions})
	}
	findings := make([]packagedomain.BlockingFinding, 0, len(value.BlockingFindings))
	for _, finding := range value.BlockingFindings {
		findings = append(findings, packagedomain.BlockingFinding(finding))
	}
	exceptions := make([]packagedomain.AcceptedExceptionSnapshot, 0, len(value.AcceptedExceptions))
	for _, exception := range value.AcceptedExceptions {
		exceptions = append(exceptions, packagedomain.AcceptedExceptionSnapshot(exception))
	}
	return packagedomain.ReleaseReadinessReport{
		ReportType: value.ReportType, TemplateVersion: value.TemplateVersion, ReleaseID: value.ReleaseID, Result: value.Result, PolicySet: value.PolicySet,
		Summary: packagedomain.ReadinessSummary(value.Summary), Checks: checks, Sections: sections, BlockingFindings: findings, AcceptedExceptions: exceptions,
		Gaps: value.Gaps, MissingEvidence: value.MissingEvidence, FailedPolicies: value.FailedPolicies, KnownLimitations: value.KnownLimitations,
		NonClaims: value.NonClaims, Assumptions: value.Assumptions, Limitations: value.Limitations, Metadata: value.Metadata, GeneratedAt: value.GeneratedAt,
	}
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
	if _, fixture := s.releaseBundleCommands.(packageFixtureCommands); s.releaseBundleCommands == nil || fixture {
		s.releaseBundleCommands = commands
	}
	if _, fixture := s.customerPackageCreationCommands.(packageFixtureCommands); s.customerPackageCreationCommands == nil || fixture {
		s.customerPackageCreationCommands = commands
	}
	if _, fixture := s.redactionProfileCommands.(packageFixtureCommands); s.redactionProfileCommands == nil || fixture {
		s.redactionProfileCommands = commands
	}
	if _, fixture := s.customerPackageAccessCommands.(packageFixtureCommands); s.customerPackageAccessCommands == nil || fixture {
		s.customerPackageAccessCommands = commands
	}
	if _, fixture := s.htmlReportCommands.(packageFixtureCommands); s.htmlReportCommands == nil || fixture {
		s.htmlReportCommands = commands
	}
	if query, fixture := s.releaseReadinessReportQuery.(packageReadinessFixtureQuery); s.releaseReadinessReportQuery == nil || fixture {
		query.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.releaseReadinessReportQuery = query
	}
}

var (
	_ ReportTemplateCommands          = packageFixtureCommands{}
	_ BundleImportCommand             = packageFixtureCommands{}
	_ EvidenceBundleCommands          = packageFixtureCommands{}
	_ ReleaseBundleCommands           = packageFixtureCommands{}
	_ CustomerPackageCreationCommands = packageFixtureCommands{}
	_ RedactionProfileCommands        = packageFixtureCommands{}
	_ CustomerPackageAccessCommands   = packageFixtureCommands{}
	_ HTMLReportCommands              = packageFixtureCommands{}
	_ ReleaseReadinessReportQuery     = packageReadinessFixtureQuery{}
)
