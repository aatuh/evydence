package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

type releaseEvidenceService struct {
	ledger *Ledger
}

func (l *Ledger) releaseEvidenceService() releaseEvidenceService {
	return releaseEvidenceService{ledger: l}
}

func (l *Ledger) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	return l.releaseEvidenceService().CreateProduct(ctx, actor, name, slug)
}

func (l *Ledger) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	return l.releaseEvidenceService().ListProducts(ctx, actor)
}

func (l *Ledger) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	return l.releaseEvidenceService().CreateProject(ctx, actor, productID, name)
}

func (l *Ledger) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	return l.releaseEvidenceService().CreateRelease(ctx, actor, productID, version)
}

func (l *Ledger) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	return l.releaseEvidenceService().GetRelease(ctx, actor, releaseID)
}

func (l *Ledger) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	return l.releaseEvidenceService().FreezeRelease(ctx, actor, releaseID)
}

func (l *Ledger) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	return l.releaseEvidenceService().ApproveRelease(ctx, actor, releaseID)
}

func (l *Ledger) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	return l.releaseEvidenceService().RegisterArtifact(ctx, actor, name, mediaType, digest, size)
}

func (l *Ledger) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	return l.releaseEvidenceService().CreateEvidence(ctx, actor, in)
}

func (l *Ledger) GetEvidence(ctx context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	return l.releaseEvidenceService().GetEvidence(ctx, actor, id)
}

func (l *Ledger) ListEvidence(ctx context.Context, actor domain.Actor, releaseID, typ string) ([]domain.EvidenceItem, error) {
	return l.releaseEvidenceService().ListEvidence(ctx, actor, releaseID, typ)
}

func (l *Ledger) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	return l.releaseEvidenceService().SupersedeEvidence(ctx, actor, id, replacementID, reason)
}

func (l *Ledger) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	return l.releaseEvidenceService().LinkEvidence(ctx, actor, id, targetType, targetID)
}

func (l *Ledger) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	return l.releaseEvidenceService().UploadSBOM(ctx, actor, releaseID, artifactID, raw)
}

func (l *Ledger) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	return l.releaseEvidenceService().UploadVulnerabilityScan(ctx, actor, raw)
}

func (l *Ledger) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	return l.releaseEvidenceService().UploadOpenAPIContract(ctx, actor, productID, releaseID, version, raw)
}

func (l *Ledger) GetSBOM(ctx context.Context, actor domain.Actor, id string) (domain.SBOM, error) {
	return l.releaseEvidenceService().GetSBOM(ctx, actor, id)
}

func (l *Ledger) ListSBOMComponents(ctx context.Context, actor domain.Actor, in ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error) {
	return l.releaseEvidenceService().ListSBOMComponents(ctx, actor, in)
}

func (l *Ledger) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (domain.VulnerabilityScan, error) {
	return l.releaseEvidenceService().GetVulnerabilityScan(ctx, actor, id)
}

func (l *Ledger) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (domain.OpenAPIContract, error) {
	return l.releaseEvidenceService().GetOpenAPIContract(ctx, actor, id)
}

func (l *Ledger) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	return l.releaseEvidenceService().UploadVEX(ctx, actor, releaseID, artifactID, raw)
}

func (l *Ledger) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (domain.VEXDocument, error) {
	return l.releaseEvidenceService().GetVEXDocument(ctx, actor, id)
}

func (l *Ledger) GetVEXImportReport(ctx context.Context, actor domain.Actor, vexID string) (domain.VEXImportReport, error) {
	return l.releaseEvidenceService().GetVEXImportReport(ctx, actor, vexID)
}

func (l *Ledger) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, findingID string, in CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	return l.releaseEvidenceService().CreateVulnerabilityDecision(ctx, actor, findingID, in)
}

func (l *Ledger) ListVulnerabilityDecisions(ctx context.Context, actor domain.Actor, in ListVulnerabilityDecisionsInput) ([]domain.VulnerabilityDecision, error) {
	return l.releaseEvidenceService().ListVulnerabilityDecisions(ctx, actor, in)
}

func (l *Ledger) VulnerabilityDecisionSummaryReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityDecisionSummaryReport, error) {
	return l.releaseEvidenceService().VulnerabilityDecisionSummaryReport(ctx, actor, releaseID)
}

func (l *Ledger) CreateException(ctx context.Context, actor domain.Actor, in CreateExceptionInput) (domain.Exception, error) {
	return l.releaseEvidenceService().CreateException(ctx, actor, in)
}

func (l *Ledger) ListExceptions(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.Exception, error) {
	return l.releaseEvidenceService().ListExceptions(ctx, actor, releaseID)
}

func (l *Ledger) ApproveException(ctx context.Context, actor domain.Actor, id string) (domain.Exception, error) {
	return l.releaseEvidenceService().ApproveException(ctx, actor, id)
}

func (l *Ledger) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
	return l.releaseEvidenceService().ReleaseReadinessReport(ctx, actor, releaseID)
}
