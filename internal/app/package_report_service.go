package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
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

func (l *Ledger) IncidentReport(ctx context.Context, actor domain.Actor, incidentID string) (domain.IncidentReport, error) {
	return l.packageReportService().IncidentReport(ctx, actor, incidentID)
}

func (l *Ledger) VulnerabilityPostureReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityPostureReport, error) {
	return l.packageReportService().VulnerabilityPostureReport(ctx, actor, releaseID)
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

func (l *Ledger) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	return l.packageReportService().CreateRedactionProfile(ctx, actor, in)
}

func (l *Ledger) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	return l.packageReportService().CreateCustomerSecurityPackage(ctx, actor, in)
}

func (l *Ledger) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
	return l.packageReportService().AccessCustomerSecurityPackage(ctx, actor, id)
}

func (l *Ledger) ExportCustomerSecurityPackageArchive(ctx context.Context, actor domain.Actor, id string) (CustomerPackageArchive, error) {
	return l.packageReportService().ExportCustomerSecurityPackageArchive(ctx, actor, id)
}

func (l *Ledger) ExportCustomerPortalPackageArchive(ctx context.Context, token string) (CustomerPackageArchive, error) {
	return l.packageReportService().ExportCustomerPortalPackageArchive(ctx, token)
}

func (l *Ledger) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
	return l.packageReportService().SecurityReviewPackageReport(ctx, actor, packageID)
}

func (l *Ledger) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
	return l.packageReportService().CRAReadinessHTMLPackage(ctx, actor, productID, releaseID)
}

func (l *Ledger) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
	return l.packageReportService().CreateCustomReportTemplate(ctx, actor, in)
}

func (l *Ledger) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
	return l.packageReportService().RenderCustomReport(ctx, actor, in)
}

func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	return l.packageReportService().ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
}

func (l *Ledger) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
	return l.packageReportService().ImportEvidenceBundle(ctx, actor, bundle)
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
