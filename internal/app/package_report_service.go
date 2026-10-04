package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type packageReportService struct {
	ledger *Ledger
}

func (l *Ledger) packageReportService() packageReportService {
	return packageReportService{ledger: l}
}

func (l *Ledger) MissingEvidenceReport(ctx context.Context, actor domain.Actor, releaseID string) (map[string]any, error) {
	return l.packageReportService().MissingEvidenceReport(ctx, actor, releaseID)
}

func (l *Ledger) ControlCoverageReport(ctx context.Context, actor domain.Actor, in ControlCoverageReportInput) (domain.ControlCoverageReport, error) {
	return l.packageReportService().ControlCoverageReport(ctx, actor, in)
}

func (l *Ledger) CRAReadinessReport(ctx context.Context, actor domain.Actor, in CRAReadinessReportInput) (domain.CRAReadinessReport, error) {
	return l.packageReportService().CRAReadinessReport(ctx, actor, in)
}

func (l *Ledger) CRAVulnerabilityHandlingReport(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.CRAVulnerabilityHandlingReport, error) {
	return l.packageReportService().CRAVulnerabilityHandlingReport(ctx, actor, productID, releaseID)
}

func (l *Ledger) SecurityUpdateEvidenceReport(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.SecurityUpdateEvidenceReport, error) {
	return l.packageReportService().SecurityUpdateEvidenceReport(ctx, actor, productID, releaseID)
}

func (l *Ledger) IncidentReport(ctx context.Context, actor domain.Actor, incidentID string) (domain.IncidentReport, error) {
	return l.packageReportService().IncidentReport(ctx, actor, incidentID)
}

func (l *Ledger) VulnerabilityPostureReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityPostureReport, error) {
	return l.packageReportService().VulnerabilityPostureReport(ctx, actor, releaseID)
}

func (l *Ledger) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
	value, err := l.packageCommands.ReleaseReadinessReport(ctx, actor, releaseID)
	return releaseReadinessReportFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateReleaseBundle(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseBundle, error) {
	value, err := l.packageCommands.CreateReleaseBundle(ctx, actor, releaseID)
	return domain.ReleaseBundleFromContextModel(value), fromPackageContextError(err)
}

// Explicit local-memory replay uses current scoped access without generating
// a manifest, signature, audit entry or worker job. The PostgreSQL runtime
// binds the native Package command guard instead of this compatibility helper.
func (l *Ledger) AuthorizeReleaseBundleCreation(ctx context.Context, a domain.Actor, raw string) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeBundleWrite); err != nil {
		return err
	}
	id, err := packageapp.NormalizeReleaseBundleID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeProductReleaseLocked(a, ScopeBundleWrite, "", id)
	return err
}

func (l *Ledger) RetentionReport(ctx context.Context, actor domain.Actor, scopeType, scopeID string) (domain.RetentionReport, error) {
	return l.packageReportService().RetentionReport(ctx, actor, scopeType, scopeID)
}

func (l *Ledger) CreateQuestionnaireTemplate(ctx context.Context, actor domain.Actor, in CreateQuestionnaireTemplateInput) (domain.QuestionnaireTemplate, error) {
	return l.packageReportService().CreateQuestionnaireTemplate(ctx, actor, in)
}

func (l *Ledger) CreateQuestionnairePackage(ctx context.Context, actor domain.Actor, in CreateQuestionnairePackageInput) (domain.QuestionnairePackage, error) {
	return l.packageReportService().CreateQuestionnairePackage(ctx, actor, in)
}

func (l *Ledger) CreateQuestionnaireAnswerLibraryEntry(ctx context.Context, actor domain.Actor, in CreateQuestionnaireAnswerLibraryEntryInput) (domain.QuestionnaireAnswerLibraryEntry, error) {
	return l.packageReportService().CreateQuestionnaireAnswerLibraryEntry(ctx, actor, in)
}

func (l *Ledger) ListQuestionnaireAnswerLibrary(ctx context.Context, actor domain.Actor, in ListQuestionnaireAnswerLibraryInput) ([]domain.QuestionnaireAnswerLibraryEntry, error) {
	return l.packageReportService().ListQuestionnaireAnswerLibrary(ctx, actor, in)
}

func (l *Ledger) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	value, err := l.packageCommands.CreateRedactionProfile(ctx, actor, packageapp.CreateRedactionProfileInput{
		Name: in.Name, Description: in.Description, Preset: in.Preset,
		AllowedTypes: append([]string(nil), in.AllowedTypes...), ExcludedFields: append([]string(nil), in.ExcludedFields...),
	})
	return redactionProfileFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	value, err := l.packageCommands.CreateCustomerSecurityPackage(ctx, actor, packageapp.CreateCustomerPackageInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: in.RedactionProfileID,
		Title: in.Title, ExpiresAt: in.ExpiresAt,
	})
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}

func (l *Ledger) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
	value, err := l.packageCommands.AccessCustomerSecurityPackage(ctx, actor, id)
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}

func (l *Ledger) ExportCustomerSecurityPackageArchive(ctx context.Context, actor domain.Actor, id string) (CustomerPackageArchive, error) {
	return l.packageReportService().ExportCustomerSecurityPackageArchive(ctx, actor, id)
}

func (l *Ledger) ExportCustomerPortalPackageArchive(ctx context.Context, token string) (CustomerPackageArchive, error) {
	return l.packageReportService().ExportCustomerPortalPackageArchive(ctx, token)
}

func (l *Ledger) ExportCustomerPortalPackageArchiveWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (CustomerPackageArchive, error) {
	return l.packageReportService().ExportCustomerPortalPackageArchiveWithAcceptance(ctx, token, in)
}

func (l *Ledger) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
	return l.packageReportService().SecurityReviewPackageReport(ctx, actor, packageID)
}

func (l *Ledger) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
	value, err := l.packageCommands.CRAReadinessHTMLPackage(ctx, actor, productID, releaseID)
	return htmlReportPackageFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
	value, err := l.packageCommands.CreateCustomReportTemplate(ctx, actor, packageapp.CreateReportTemplateInput{
		Name: in.Name, Version: in.Version, ReportType: in.ReportType,
		AllowedFields: append([]string(nil), in.AllowedFields...), Template: in.Template,
	})
	return customReportTemplateFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
	value, err := l.packageCommands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{
		TemplateID: in.TemplateID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
	})
	return renderedCustomReportFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	value, err := l.packageCommands.ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
	return evidenceBundleFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
	value, err := l.packageCommands.ImportEvidenceBundle(ctx, actor, evidenceBundleToPackageContext(bundle))
	return evidenceBundleImportFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateEvidenceSummary(ctx context.Context, actor domain.Actor, in CreateEvidenceSummaryInput) (domain.EvidenceSummary, error) {
	return l.packageReportService().CreateEvidenceSummary(ctx, actor, in)
}

func (l *Ledger) CreateQuestionnaireDraft(ctx context.Context, actor domain.Actor, in CreateQuestionnaireDraftInput) (domain.QuestionnaireDraft, error) {
	return l.packageReportService().CreateQuestionnaireDraft(ctx, actor, in)
}

func (l *Ledger) CreatePDFReportPackage(ctx context.Context, actor domain.Actor, in CreatePDFReportPackageInput) (domain.PDFReportPackage, error) {
	return l.packageReportService().CreatePDFReportPackage(ctx, actor, in)
}

func (l *Ledger) GenerateAnomalyReport(ctx context.Context, actor domain.Actor, in AnomalyReportInput) (domain.AnomalyReport, error) {
	return l.packageReportService().GenerateAnomalyReport(ctx, actor, in)
}
