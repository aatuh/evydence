package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (l *Ledger) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	value, err := l.releaseCommands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: name, Slug: slug})
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetProduct(ctx context.Context, actor domain.Actor, id string) (domain.Product, error) {
	value, err := l.releaseCommands.GetProduct(ctx, actor, id)
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	value, err := l.releaseCommands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: productID, Name: name})
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	value, err := l.releaseCommands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: productID, Version: version})
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	value, err := l.releaseCommands.GetRelease(ctx, actor, releaseID)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.FreezeRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.ApproveRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	value, err := l.releaseCommands.RegisterArtifact(ctx, actor, releaseapp.RegisterArtifactInput{Name: name, MediaType: mediaType, Digest: digest, Size: size})
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetArtifact(ctx context.Context, actor domain.Actor, id string) (domain.Artifact, error) {
	value, err := l.releaseCommands.GetArtifact(ctx, actor, id)
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	subjects := make([]evidencedomain.SubjectRef, 0, len(in.SubjectRefs))
	for _, subject := range in.SubjectRefs {
		subjects = append(subjects, evidencedomain.SubjectRef{Type: subject.Type, ID: subject.ID, Digest: subject.Digest})
	}
	value, err := l.evidenceCommands.CreateEvidence(ctx, actor, evidenceapp.CreateEvidenceInput{
		ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID,
		Type: in.Type, Subtype: in.Subtype, Title: in.Title, SourceSystem: in.SourceSystem, SourceIdentity: cloneMap(in.SourceIdentity),
		CollectorID: in.CollectorID, ObservedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash,
		PayloadMediaType: in.PayloadMediaType, PayloadSize: in.PayloadSize, StagedPayload: objectPayloadToEvidenceContext(in.StagedPayload),
		SubjectRefs: subjects, Metadata: cloneMap(in.Metadata), Tags: append([]string(nil), in.Tags...), Limitations: append([]string(nil), in.Limitations...),
	})
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.SupersedeEvidence(ctx, actor, id, replacementID, reason)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.LinkEvidence(ctx, actor, id, targetType, targetID)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSBOM(ctx, actor, releaseID, artifactID, raw)
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSBOMPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion. CycloneDX 1.6 schema validation and normalization
// consume the same bounded bytes before evidence or object-store side effects.
func (l *Ledger) UploadSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSPDXSBOMPayload accepts an SPDX JSON source whose bytes are validated,
// normalized, and staged as the same digest-bound payload.
func (l *Ledger) UploadSPDXSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	value, err := l.evidenceCommands.UploadVulnerabilityScan(ctx, actor, raw)
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVulnerabilityScanPayload accepts a repeatable pre-hashed payload
// source for streaming HTTP ingestion.
func (l *Ledger) UploadVulnerabilityScanPayload(ctx context.Context, actor domain.Actor, source PayloadSource) (domain.VulnerabilityScan, error) {
	value, err := l.evidenceCommands.UploadVulnerabilityScanPayload(ctx, actor, payloadSourceToEvidenceContext(source))
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	value, err := l.evidenceCommands.UploadOpenAPIContract(ctx, actor, productID, releaseID, version, raw)
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadOpenAPIContractPayload accepts a repeatable pre-hashed payload source
// for streaming HTTP ingestion.
func (l *Ledger) UploadOpenAPIContractPayload(ctx context.Context, actor domain.Actor, productID, releaseID, version string, source PayloadSource) (domain.OpenAPIContract, error) {
	value, err := l.evidenceCommands.UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, payloadSourceToEvidenceContext(source))
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	value, err := l.evidenceCommands.UploadVEX(ctx, actor, releaseID, artifactID, raw)
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVEXPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion.
func (l *Ledger) UploadVEXPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.VEXDocument, error) {
	value, err := l.evidenceCommands.UploadVEXPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}
