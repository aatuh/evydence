package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical commands retained only for characterization tests.

func (l *Ledger) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	value, err := l.legacyEvidenceCommands().UploadSBOM(ctx, actor, releaseID, artifactID, raw)
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSBOMPayload accepts a repeatable pre-hashed payload source for
// streaming HTTP ingestion. CycloneDX 1.6 schema validation and normalization
// consume the same bounded bytes before evidence or object-store side effects.
func (l *Ledger) UploadSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.legacyEvidenceCommands().UploadSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadSPDXSBOMPayload accepts an SPDX JSON source whose bytes are validated,
// normalized, and staged as the same digest-bound payload.
func (l *Ledger) UploadSPDXSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	value, err := l.legacyEvidenceCommands().UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, payloadSourceToEvidenceContext(source))
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	value, err := l.legacyEvidenceCommands().UploadOpenAPIContract(ctx, actor, productID, releaseID, version, raw)
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadOpenAPIContractPayload accepts a repeatable pre-hashed payload source
// for streaming HTTP ingestion.
func (l *Ledger) UploadOpenAPIContractPayload(ctx context.Context, actor domain.Actor, productID, releaseID, version string, source PayloadSource) (domain.OpenAPIContract, error) {
	value, err := l.legacyEvidenceCommands().UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, payloadSourceToEvidenceContext(source))
	return openAPIContractFromEvidenceContext(value), fromEvidenceContextError(err)
}
