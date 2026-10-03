package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	scannerparser "github.com/aatuh/evydence/internal/app/parsers/scanners"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type ledgerEvidencePayloadParser struct{}

func (ledgerEvidencePayloadParser) ProbeVulnerabilityScanScope(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.VulnerabilityScanScope, error) {
	if err := ctx.Err(); err != nil {
		return evidenceapp.VulnerabilityScanScope{}, err
	}
	var releaseID string
	err := parseDigestBoundEvidenceSource(source, func(reader io.Reader) error {
		var err error
		releaseID, err = scannerparser.ProbeReleaseIDBoundedReader(reader, scannerparser.DefaultLimits(EvidenceDocumentLimit))
		return err
	})
	if err != nil {
		if errors.Is(err, scannerparser.ErrInvalid) {
			return evidenceapp.VulnerabilityScanScope{}, evidenceapp.ErrValidation
		}
		return evidenceapp.VulnerabilityScanScope{}, toEvidenceContextError(err)
	}
	return evidenceapp.VulnerabilityScanScope{ReleaseID: releaseID}, nil
}

func (ledgerEvidencePayloadParser) ParseSBOM(_ context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedSBOM, error) {
	legacySource := payloadSourceFromEvidenceContext(source)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "cyclonedx":
		validator, err := productionCycloneDXValidator()
		if err != nil {
			return evidenceapp.ParsedSBOM{}, err
		}
		normalized, err := validateAndNormalizeCycloneDXSource(legacySource, validator)
		if err != nil {
			return evidenceapp.ParsedSBOM{}, toEvidenceContextError(err)
		}
		return evidenceapp.ParsedSBOM{
			Format: "cyclonedx", SpecVersion: normalized.SpecVersion, ParserVersion: normalized.ParserVersion,
			Components: sbomComponentsToEvidenceContext(normalized.Components), Metadata: normalized.evidenceMetadata(),
			Limitations: normalized.limitations(),
		}, nil
	case "spdx":
		normalized, err := validateAndNormalizeSPDXSource(legacySource)
		if err != nil {
			return evidenceapp.ParsedSBOM{}, toEvidenceContextError(err)
		}
		return evidenceapp.ParsedSBOM{
			Format: "spdx", SpecVersion: normalized.SpecVersion, ParserVersion: normalized.ParserVersion,
			Components: sbomComponentsToEvidenceContext(normalized.Components), Metadata: normalized.evidenceMetadata(),
			Limitations: normalized.limitations(),
		}, nil
	default:
		return evidenceapp.ParsedSBOM{}, evidenceapp.ErrValidation
	}
}

func (ledgerEvidencePayloadParser) ParseVulnerabilityScan(_ context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedVulnerabilityScan, error) {
	var parsed scannerparser.Result
	err := parseDigestBoundEvidenceSource(source, func(reader io.Reader) error {
		var err error
		parsed, err = scannerparser.ParseBoundedReader(reader, scannerparser.DefaultLimits(EvidenceDocumentLimit))
		return err
	})
	if err != nil {
		if errors.Is(err, scannerparser.ErrInvalid) {
			return evidenceapp.ParsedVulnerabilityScan{}, evidenceapp.ErrValidation
		}
		return evidenceapp.ParsedVulnerabilityScan{}, toEvidenceContextError(err)
	}
	findings := make([]evidencedomain.VulnerabilityFinding, 0, len(parsed.Findings))
	summary := map[string]int{}
	for _, finding := range parsed.Findings {
		summary[finding.Severity]++
		findings = append(findings, evidencedomain.VulnerabilityFinding{
			Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity,
			State: finding.State, SeveritySource: finding.SeveritySource, FixVersion: finding.FixVersion,
			Identity: evidencedomain.VulnerabilityIdentity{
				CVE: finding.Identity.CVE, GHSA: finding.Identity.GHSA, OSV: finding.Identity.OSV,
				VendorAdvisory: finding.Identity.VendorAdvisory, PURL: finding.Identity.PURL, CPE: finding.Identity.CPE,
			},
		})
	}
	metadata := WithParserProvenance(map[string]any{
		"scanner": parsed.Scanner, "adapter": parsed.Adapter, "adapter_version": parsed.AdapterVersion,
		"source_schema": parsed.SourceSchema, "target_ref": parsed.TargetRef,
	}, ParserProvenance{
		Name: parsed.Adapter, Version: parsed.AdapterVersion, SourceSchema: parsed.SourceSchema,
		NormalizedSchema: "evydence-vulnerability-finding.v1", ReplayStatus: ParserReplayStatusOriginal,
	})
	return evidenceapp.ParsedVulnerabilityScan{
		ReleaseID: parsed.ReleaseID, Scanner: parsed.Scanner, Adapter: parsed.Adapter,
		AdapterVersion: parsed.AdapterVersion, SourceSchema: parsed.SourceSchema, TargetRef: parsed.TargetRef,
		Summary: summary, Findings: findings, Metadata: metadata,
	}, nil
}

func (ledgerEvidencePayloadParser) ParseOpenAPIContract(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedOpenAPIContract, error) {
	var document *openapi3.T
	err := parseDigestBoundEvidenceSource(source, func(reader io.Reader) error {
		var err error
		document, err = openapi3.NewLoader().LoadFromIoReader(reader)
		if err != nil {
			return err
		}
		return document.Validate(ctx)
	})
	if err != nil || document == nil || document.Paths == nil || strings.TrimSpace(document.OpenAPI) == "" {
		return evidenceapp.ParsedOpenAPIContract{}, evidenceapp.ErrValidation
	}
	operations := extractOpenAPIOperations(document)
	pathCount := len(document.Paths.Map())
	return evidenceapp.ParsedOpenAPIContract{
		ParserVersion: ParserVersionOpenAPIJSON, SourceSchema: "openapi-" + document.OpenAPI,
		PathCount: pathCount, Operations: openAPIOperationsToEvidenceContext(operations),
		Metadata: WithParserProvenance(map[string]any{"path_count": pathCount}, ParserProvenance{
			Name: "openapi", Version: ParserVersionOpenAPIJSON, SourceSchema: "openapi-" + document.OpenAPI,
			NormalizedSchema: "evydence-openapi-contract.v1", ReplayStatus: ParserReplayStatusOriginal,
		}),
	}, nil
}

func (ledgerEvidencePayloadParser) ParseVEX(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedVEX, error) {
	if err := ctx.Err(); err != nil {
		return evidenceapp.ParsedVEX{}, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	var parsed vexparser.Document
	err := parseDigestBoundEvidenceSource(source, func(reader io.Reader) error {
		raw, err := io.ReadAll(io.LimitReader(reader, EvidenceDocumentLimit+1))
		if err != nil || !ValidPayloadSize(int64(len(raw)), EvidenceDocumentLimit) {
			return ErrValidation
		}
		switch format {
		case "openvex":
			parsed, err = vexparser.ParseOpenVEX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
		case "cyclonedx":
			parsed, err = vexparser.ParseCycloneDX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
		default:
			return ErrValidation
		}
		return err
	})
	if err != nil {
		if errors.Is(err, vexparser.ErrInvalid) || errors.Is(err, ErrValidation) {
			return evidenceapp.ParsedVEX{}, evidenceapp.ErrValidation
		}
		return evidenceapp.ParsedVEX{}, toEvidenceContextError(err)
	}
	if parsed.Format != format {
		return evidenceapp.ParsedVEX{}, evidenceapp.ErrValidation
	}

	parserVersion, sourceSchema, parserName := ParserVersionOpenVEXJSON, "openvex-json", "openvex"
	if format == "cyclonedx" {
		parserVersion, sourceSchema, parserName = ParserVersionCycloneDXVEXJSON, "cyclonedx-vex-"+parsed.Version, "cyclonedx-vex"
	}
	statusSummary := map[string]int{}
	invalidStatements := []evidencedomain.VEXImportIssue{}
	statements := []evidenceapp.VEXDecisionStatement{}
	validStatements := 0
	for index, statement := range parsed.Statements {
		if format == "cyclonedx" && strings.TrimSpace(statement.Vulnerability) == "" {
			invalidStatements = append(invalidStatements, evidencedomain.VEXImportIssue{StatementIndex: index + 1, Code: "missing_vulnerability", Detail: "CycloneDX VEX vulnerability is missing an id."})
			continue
		}
		if format == "cyclonedx" && strings.TrimSpace(statement.Status) == "" {
			invalidStatements = append(invalidStatements, evidencedomain.VEXImportIssue{StatementIndex: index + 1, Code: "unsupported_analysis_state", Detail: "CycloneDX VEX vulnerability has an unsupported analysis state."})
			continue
		}
		validStatements++
		statusSummary[statement.Status]++
		statements = append(statements, evidenceapp.VEXDecisionStatement{
			StatementIndex: index + 1, Vulnerability: statement.Vulnerability, Products: append([]string(nil), statement.Products...),
			Status: statement.Status, Justification: statement.Justification, ImpactStatement: statement.ImpactStatement, ActionStatement: statement.ActionStatement,
		})
	}
	if validStatements == 0 {
		return evidenceapp.ParsedVEX{}, evidenceapp.ErrValidation
	}
	warnings := append([]string(nil), parsed.Warnings...)
	if len(invalidStatements) > 0 {
		warnings = append(warnings, "One or more CycloneDX VEX vulnerabilities were skipped because required analysis fields were missing or unsupported.")
	}
	metadata := WithParserProvenance(map[string]any{
		"format": format, "statement_count": len(parsed.Statements),
	}, ParserProvenance{
		Name: parserName, Version: parserVersion, SourceSchema: sourceSchema,
		NormalizedSchema: "evydence-vex.v1", Warnings: warnings, ReplayStatus: ParserReplayStatusOriginal,
	})
	if format == "cyclonedx" {
		metadata["spec_version"] = parsed.Version
	}
	return evidenceapp.ParsedVEX{
		Format: format, Author: parsed.Author, Version: parsed.Version, ParserVersion: parserVersion,
		StatementCount: len(parsed.Statements), ValidStatementCount: validStatements, StatusSummary: statusSummary,
		Statements: statements, Warnings: warnings, InvalidStatements: invalidStatements, Metadata: metadata,
	}, nil
}

type ledgerEvidenceSourceObjectIngestion struct{ ledger *Ledger }

func (s ledgerEvidenceSourceObjectIngestion) StagePayloadSource(ctx context.Context, tenantID, mediaType string, source evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	payload, err := s.ledger.stagePayloadSource(ctx, tenantID, mediaType, payloadSourceFromEvidenceContext(source))
	if err != nil {
		return evidenceapp.StagedPayload{}, toEvidenceContextError(err)
	}
	return objectPayloadToEvidenceContext(payload), nil
}

func payloadSourceFromEvidenceContext(source evidenceapp.PayloadSource) PayloadSource {
	return PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}
}

func payloadSourceToEvidenceContext(source PayloadSource) evidenceapp.PayloadSource {
	return evidenceapp.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}
}

func parseDigestBoundEvidenceSource(source evidenceapp.PayloadSource, parse func(io.Reader) error) error {
	legacy := payloadSourceFromEvidenceContext(source)
	if validatePayloadSource(legacy, EvidenceDocumentLimit) != nil || parse == nil {
		return ErrValidation
	}
	reader, err := legacy.Open()
	if err != nil {
		return ErrValidation
	}
	hasher, counter := sha256.New(), &payloadByteCounter{}
	parseErr := parse(io.TeeReader(reader, io.MultiWriter(hasher, counter)))
	closeErr := reader.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return ErrValidation
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if counter.n != source.Size || digest != source.Digest {
		return ErrValidation
	}
	return nil
}

func sbomComponentsToEvidenceContext(values []domain.SBOMComponent) []evidencedomain.SBOMComponent {
	result := make([]evidencedomain.SBOMComponent, 0, len(values))
	for _, value := range values {
		result = append(result, sbomComponentToEvidenceContext(value))
	}
	return result
}

func openAPIOperationsToEvidenceContext(values []domain.OpenAPIOperation) []evidencedomain.OpenAPIOperation {
	result := make([]evidencedomain.OpenAPIOperation, 0, len(values))
	for _, value := range values {
		result = append(result, evidencedomain.OpenAPIOperation{
			Path: value.Path, Method: value.Method, OperationID: value.OperationID, Deprecated: value.Deprecated,
			RequestBodyRequired: value.RequestBodyRequired, RequiredRequestFields: append([]string(nil), value.RequiredRequestFields...),
			ResponseStatuses: append([]string(nil), value.ResponseStatuses...),
		})
	}
	return result
}

func extractOpenAPIOperations(doc *openapi3.T) []domain.OpenAPIOperation {
	if doc == nil || doc.Paths == nil {
		return nil
	}
	paths := doc.Paths.Map()
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	out := make([]domain.OpenAPIOperation, 0)
	for _, path := range pathNames {
		item := paths[path]
		for _, methodOperation := range openAPIMethodOperations(item) {
			operation := methodOperation.operation
			if operation == nil {
				continue
			}
			out = append(out, domain.OpenAPIOperation{
				Path: path, Method: strings.ToUpper(methodOperation.method), OperationID: operation.OperationID,
				Deprecated: operation.Deprecated, RequestBodyRequired: openAPIRequestBodyRequired(operation),
				RequiredRequestFields: openAPIRequiredRequestFields(operation), ResponseStatuses: openAPIResponseStatuses(operation),
			})
		}
	}
	return out
}

type openAPIMethodOperation struct {
	method    string
	operation *openapi3.Operation
}

func openAPIMethodOperations(item *openapi3.PathItem) []openAPIMethodOperation {
	if item == nil {
		return nil
	}
	return []openAPIMethodOperation{
		{method: "connect", operation: item.Connect}, {method: "delete", operation: item.Delete},
		{method: "get", operation: item.Get}, {method: "head", operation: item.Head},
		{method: "options", operation: item.Options}, {method: "patch", operation: item.Patch},
		{method: "post", operation: item.Post}, {method: "put", operation: item.Put},
		{method: "trace", operation: item.Trace},
	}
}

func openAPIRequestBodyRequired(operation *openapi3.Operation) bool {
	return operation != nil && operation.RequestBody != nil && operation.RequestBody.Value != nil && operation.RequestBody.Value.Required
}

func openAPIRequiredRequestFields(operation *openapi3.Operation) []string {
	if operation == nil || operation.RequestBody == nil || operation.RequestBody.Value == nil {
		return nil
	}
	fields := map[string]struct{}{}
	for _, media := range operation.RequestBody.Value.Content {
		if media == nil || media.Schema == nil || media.Schema.Value == nil {
			continue
		}
		for _, field := range media.Schema.Value.Required {
			if field = strings.TrimSpace(field); field != "" {
				fields[field] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(fields))
	for field := range fields {
		out = append(out, field)
	}
	sort.Strings(out)
	return out
}

func openAPIResponseStatuses(operation *openapi3.Operation) []string {
	if operation == nil || operation.Responses == nil {
		return nil
	}
	statuses := make([]string, 0, len(operation.Responses.Map()))
	for status := range operation.Responses.Map() {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	return statuses
}

var _ evidenceapp.PayloadParser = ledgerEvidencePayloadParser{}
var _ evidenceapp.SourceObjectIngestion = ledgerEvidenceSourceObjectIngestion{}
