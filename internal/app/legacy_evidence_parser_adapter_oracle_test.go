package app

import (
	"context"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// Historical wrappers retain the real parsers for package-local tests only.
type ledgerEvidencePayloadParser struct{}

func (ledgerEvidencePayloadParser) ProbeVulnerabilityScanScope(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.VulnerabilityScanScope, error) {
	return (VulnerabilityScanPayloadParser{}).ProbeVulnerabilityScanScope(ctx, source)
}

func (ledgerEvidencePayloadParser) ParseSBOM(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedSBOM, error) {
	return (SBOMPayloadParser{}).ParseSBOM(ctx, format, source)
}

func (ledgerEvidencePayloadParser) ParseVulnerabilityScan(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedVulnerabilityScan, error) {
	return (VulnerabilityScanPayloadParser{}).ParseVulnerabilityScan(ctx, source)
}

func (ledgerEvidencePayloadParser) ParseOpenAPIContract(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedOpenAPIContract, error) {
	return (OpenAPIContractPayloadParser{}).ParseOpenAPIContract(ctx, source)
}

func (ledgerEvidencePayloadParser) ParseVEX(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedVEX, error) {
	return (VEXPayloadParser{}).ParseVEX(ctx, format, source)
}

type ledgerEvidenceSourceObjectIngestion struct{ ledger *Ledger }

func (s ledgerEvidenceSourceObjectIngestion) StagePayloadSource(ctx context.Context, tenantID, mediaType string, source evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	payload, err := s.ledger.stagePayloadSource(ctx, tenantID, mediaType, payloadSourceFromEvidenceContext(source))
	if err != nil {
		return evidenceapp.StagedPayload{}, toEvidenceContextError(err)
	}
	return objectPayloadToEvidenceContext(payload), nil
}

var _ evidenceapp.PayloadParser = ledgerEvidencePayloadParser{}
var _ evidenceapp.SourceObjectIngestion = ledgerEvidenceSourceObjectIngestion{}
