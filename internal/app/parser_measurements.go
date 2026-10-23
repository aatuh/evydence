package app

import (
	"context"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

// Measurements preserve command/parser results, transaction ownership and context.
func (p SBOMPayloadParser) ParseSBOM(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedSBOM, error) {
	return telemetry.Measure(ctx, telemetry.OperationParseSBOM, func(callCtx context.Context) (evidenceapp.ParsedSBOM, error) {
		return p.parseSBOM(callCtx, format, source)
	})
}

func (p VulnerabilityScanPayloadParser) ParseVulnerabilityScan(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedVulnerabilityScan, error) {
	return telemetry.Measure(ctx, telemetry.OperationParseVulnerabilityScan, func(callCtx context.Context) (evidenceapp.ParsedVulnerabilityScan, error) {
		return p.parseVulnerabilityScan(callCtx, source)
	})
}

func (p OpenAPIContractPayloadParser) ParseOpenAPIContract(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedOpenAPIContract, error) {
	return telemetry.Measure(ctx, telemetry.OperationParseOpenAPI, func(callCtx context.Context) (evidenceapp.ParsedOpenAPIContract, error) {
		return p.parseOpenAPIContract(callCtx, source)
	})
}

func (p VEXPayloadParser) ParseVEX(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedVEX, error) {
	return telemetry.Measure(ctx, telemetry.OperationParseVEX, func(callCtx context.Context) (evidenceapp.ParsedVEX, error) {
		return p.parseVEX(callCtx, format, source)
	})
}
