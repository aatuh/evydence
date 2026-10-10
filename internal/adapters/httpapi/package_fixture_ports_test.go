package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Existing local HTTP fixtures retain their real guard, redaction, signing and
// isolated replay behavior. Runtime Package ports never accept these adapters.
type packageFixtureCommands struct{ catalogFixtureCommands }

func (f packageFixtureCommands) AuthorizeReportTemplateCreation(ctx context.Context, actor domain.Actor, input packageapp.CreateReportTemplateInput) error {
	return (reportTemplateFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeReportTemplateCreation(ctx, actor, input)
}
func (f packageFixtureCommands) AuthorizeReportRendering(ctx context.Context, actor domain.Actor, input packageapp.RenderReportInput) error {
	return (reportTemplateFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeReportRendering(ctx, actor, input)
}
func (f packageFixtureCommands) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, input packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	return (reportTemplateFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateCustomReportTemplate(ctx, actor, input)
}
func (f packageFixtureCommands) RenderCustomReport(ctx context.Context, actor domain.Actor, input packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	return (reportTemplateFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).RenderCustomReport(ctx, actor, input)
}
func (f packageFixtureCommands) AuthorizeBundleImport(ctx context.Context, actor domain.Actor, bundle packagedomain.EvidenceBundle) error {
	return (bundleImportFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeBundleImport(ctx, actor, bundle)
}
func (f packageFixtureCommands) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	return (bundleImportFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).ImportEvidenceBundle(ctx, actor, bundle)
}
func (f packageFixtureCommands) AuthorizeEvidenceBundleExport(ctx context.Context, actor domain.Actor, release string, ids []string) error {
	return (evidenceBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeEvidenceBundleExport(ctx, actor, release, ids)
}
func (f packageFixtureCommands) AuthorizeEvidenceBundleReplay(ctx context.Context, actor domain.Actor, release string, ids []string) error {
	return (evidenceBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeEvidenceBundleReplay(ctx, actor, release, ids)
}
func (f packageFixtureCommands) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, release string, ids []string) (packagedomain.EvidenceBundle, error) {
	return (evidenceBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).ExportEvidenceBundle(ctx, actor, release, ids)
}

func (f packageFixtureCommands) AuthorizeReleaseBundleCreation(ctx context.Context, actor domain.Actor, release string) error {
	return (releaseBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeReleaseBundleCreation(ctx, actor, release)
}
func (f packageFixtureCommands) CreateReleaseBundle(ctx context.Context, actor domain.Actor, release string) (packagedomain.ReleaseBundle, error) {
	return (releaseBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateReleaseBundle(ctx, actor, release)
}

func (f packageFixtureCommands) AuthorizeCreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, input packageapp.CreateCustomerPackageInput) error {
	return (customerPackageFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeCreateCustomerSecurityPackage(ctx, actor, input)
}
func (f packageFixtureCommands) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, input packageapp.CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	return (customerPackageFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateCustomerSecurityPackage(ctx, actor, input)
}
func (f packageFixtureCommands) AuthorizeCreateRedactionProfile(ctx context.Context, actor domain.Actor, input packageapp.CreateRedactionProfileInput) error {
	return (redactionProfileFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeCreateRedactionProfile(ctx, actor, input)
}
func (f packageFixtureCommands) CreateRedactionProfile(ctx context.Context, actor domain.Actor, input packageapp.CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	return (redactionProfileFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateRedactionProfile(ctx, actor, input)
}
func (f packageFixtureCommands) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, product, release string) (packagedomain.HTMLReportPackage, error) {
	c, err := f.nativeHTML()
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	return c.CRAReadinessHTMLPackage(ctx, actor, product, release)
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
	if old, fixture := s.reportTemplateCommands.(reportTemplateFixtureCommands); fixture {
		old.ledger = ledger
		s.reportTemplateCommands = old
	} else if _, legacy := s.reportTemplateCommands.(packageFixtureCommands); s.reportTemplateCommands == nil || legacy {
		s.reportTemplateCommands = reportTemplateFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, fixture := s.bundleImportCommand.(bundleImportFixtureCommands); fixture {
		old.ledger = ledger
		s.bundleImportCommand = old
	} else if _, legacy := s.bundleImportCommand.(packageFixtureCommands); s.bundleImportCommand == nil || legacy {
		s.bundleImportCommand = bundleImportFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, fixture := s.evidenceBundleCommands.(evidenceBundleFixtureCommands); fixture {
		old.ledger = ledger
		s.evidenceBundleCommands = old
	} else if _, legacy := s.evidenceBundleCommands.(packageFixtureCommands); s.evidenceBundleCommands == nil || legacy {
		s.evidenceBundleCommands = evidenceBundleFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, fixture := s.releaseBundleCommands.(releaseBundleFixtureCommands); fixture {
		old.ledger = ledger
		s.releaseBundleCommands = old
	} else if _, legacy := s.releaseBundleCommands.(packageFixtureCommands); s.releaseBundleCommands == nil || legacy {
		s.releaseBundleCommands = releaseBundleFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, ok := s.customerPackageCreationCommands.(customerPackageFixtureCommands); ok {
		old.ledger = ledger
		s.customerPackageCreationCommands = old
	} else if _, fixture := s.customerPackageCreationCommands.(packageFixtureCommands); s.customerPackageCreationCommands == nil || fixture {
		s.customerPackageCreationCommands = customerPackageFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, ok := s.redactionProfileCommands.(redactionProfileFixtureCommands); ok {
		old.ledger = ledger
		s.redactionProfileCommands = old
	} else if _, legacy := s.redactionProfileCommands.(packageFixtureCommands); s.redactionProfileCommands == nil || legacy {
		s.redactionProfileCommands = redactionProfileFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, ok := s.customerPackageAccessCommands.(customerAccessFixtureCommands); ok {
		old.ledger = ledger
		s.customerPackageAccessCommands = old
	} else if s.customerPackageAccessCommands == nil {
		s.customerPackageAccessCommands = customerAccessFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
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
	_ HTMLReportCommands              = packageFixtureCommands{}
	_ ReleaseReadinessReportQuery     = packageReadinessFixtureQuery{}
)
