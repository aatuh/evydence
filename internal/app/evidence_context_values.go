package app

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

// Value mappings used by parser, worker and selected query boundaries. They do
// not construct an aggregate, read its maps or publish a service cache.
type evidenceCanonicalHasher struct{}

func (evidenceCanonicalHasher) HashEvidence(_ context.Context, item evidencedomain.EvidenceItem) (string, error) {
	return canonicalHash(evidenceFromContext(item))
}

func cloneVulnerabilityDecisionMap(values map[string]domain.VulnerabilityDecision) map[string]domain.VulnerabilityDecision {
	result := make(map[string]domain.VulnerabilityDecision, len(values))
	for id, decision := range values {
		decision.EvidenceIDs = append([]string(nil), decision.EvidenceIDs...)
		decision.SupportingRefs = cloneSubjectRefs(decision.SupportingRefs)
		decision.ReviewedAt = cloneTimePtr(decision.ReviewedAt)
		decision.ReviewDueAt = cloneTimePtr(decision.ReviewDueAt)
		result[id] = decision
	}
	return result
}

func cloneOutboxJobMap(values map[string]OutboxJob) map[string]OutboxJob {
	result := make(map[string]OutboxJob, len(values))
	for id, job := range values {
		job.Payload = cloneMap(job.Payload)
		result[id] = job
	}
	return result
}

func evidenceToContext(value domain.EvidenceItem) evidencedomain.EvidenceItem {
	return domain.EvidenceToContextModel(value)
}

func evidenceFromContext(value evidencedomain.EvidenceItem) domain.EvidenceItem {
	return domain.EvidenceFromContextModel(value)
}

func sbomToEvidenceContext(value domain.SBOM) evidencedomain.SBOM {
	var components []evidencedomain.SBOMComponent
	if value.Components != nil {
		components = make([]evidencedomain.SBOMComponent, 0, len(value.Components))
	}
	for _, component := range value.Components {
		components = append(components, sbomComponentToEvidenceContext(component))
	}
	return evidencedomain.SBOM{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		ArtifactID: value.ArtifactID, Format: value.Format, SpecVersion: value.SpecVersion,
		ComponentCount: value.ComponentCount, Components: components, CreatedAt: value.CreatedAt,
	}
}

func sbomFromEvidenceContext(value evidencedomain.SBOM) domain.SBOM {
	return domain.SBOMFromContext(value)
}

func sbomComponentToEvidenceContext(value domain.SBOMComponent) evidencedomain.SBOMComponent {
	return evidencedomain.SBOMComponent{Identity: value.Identity, Name: value.Name, Version: value.Version, PURL: value.PURL}
}

func openAPIContractToEvidenceContext(value domain.OpenAPIContract) evidencedomain.OpenAPIContract {
	var operations []evidencedomain.OpenAPIOperation
	if value.Operations != nil {
		operations = make([]evidencedomain.OpenAPIOperation, 0, len(value.Operations))
	}
	for _, operation := range value.Operations {
		operations = append(operations, evidencedomain.OpenAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID, Deprecated: operation.Deprecated,
			RequestBodyRequired:   operation.RequestBodyRequired,
			RequiredRequestFields: append([]string(nil), operation.RequiredRequestFields...),
			ResponseStatuses:      append([]string(nil), operation.ResponseStatuses...),
		})
	}
	return evidencedomain.OpenAPIContract{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		Version: value.Version, Hash: value.Hash, PathCount: value.PathCount, Operations: operations,
		EvidenceID: value.EvidenceID, CreatedAt: value.CreatedAt,
	}
}

func openAPIContractFromEvidenceContext(value evidencedomain.OpenAPIContract) domain.OpenAPIContract {
	return domain.OpenAPIContractFromContext(value)
}

func vexDocumentToEvidenceContext(value domain.VEXDocument) evidencedomain.VEXDocument {
	return evidencedomain.VEXDocument{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		ArtifactID: value.ArtifactID, Format: value.Format, Author: value.Author, Version: value.Version,
		StatementCount: value.StatementCount, StatusSummary: cloneNullableIntMap(value.StatusSummary),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func vexDocumentFromEvidenceContext(value evidencedomain.VEXDocument) domain.VEXDocument {
	return domain.VEXDocumentFromContext(value)
}

func vexImportReportToEvidenceContext(value domain.VEXImportReport) evidencedomain.VEXImportReport {
	return evidencedomain.VEXImportReport{
		ID: value.ID, TenantID: value.TenantID, VEXDocumentID: value.VEXDocumentID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, ParserVersion: value.ParserVersion, Status: value.Status,
		StatementCount: value.StatementCount, DecisionsCreated: value.DecisionsCreated, DecisionsSuperseded: value.DecisionsSuperseded,
		UnsupportedFields: append([]string(nil), value.UnsupportedFields...), Warnings: append([]string(nil), value.Warnings...),
		InvalidStatements: vexImportIssuesToEvidenceContext(value.InvalidStatements), MappingFailures: vexImportIssuesToEvidenceContext(value.MappingFailures),
		FailureCode: value.FailureCode, FailureDetail: value.FailureDetail, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func vexImportReportFromEvidenceContext(value evidencedomain.VEXImportReport) domain.VEXImportReport {
	return domain.VEXImportReportFromContext(value)
}

func vexImportIssuesToEvidenceContext(values []domain.VEXImportIssue) []evidencedomain.VEXImportIssue {
	result := make([]evidencedomain.VEXImportIssue, 0, len(values))
	for _, value := range values {
		result = append(result, evidencedomain.VEXImportIssue{StatementIndex: value.StatementIndex, Code: value.Code, Detail: value.Detail})
	}
	return result
}

func vulnerabilityScanFromEvidenceContext(value evidencedomain.VulnerabilityScan) domain.VulnerabilityScan {
	return domain.VulnerabilityScanFromContext(value)
}

func vulnerabilityScanToEvidenceContext(value domain.VulnerabilityScan) evidencedomain.VulnerabilityScan {
	var findings []evidencedomain.VulnerabilityFinding
	if value.Findings != nil {
		findings = make([]evidencedomain.VulnerabilityFinding, 0, len(value.Findings))
	}
	for _, finding := range value.Findings {
		findings = append(findings, evidencedomain.VulnerabilityFinding{
			ID: finding.ID, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity,
			State: finding.State, SeveritySource: finding.SeveritySource, FixVersion: finding.FixVersion,
			Identity: evidencedomain.VulnerabilityIdentity{
				CVE: finding.Identity.CVE, GHSA: finding.Identity.GHSA, OSV: finding.Identity.OSV,
				VendorAdvisory: finding.Identity.VendorAdvisory, PURL: finding.Identity.PURL, CPE: finding.Identity.CPE,
			},
		})
	}
	return evidencedomain.VulnerabilityScan{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID,
		Scanner: value.Scanner, Adapter: value.Adapter, AdapterVersion: value.AdapterVersion,
		SourceSchema: value.SourceSchema, TargetRef: value.TargetRef, Summary: cloneNullableIntMap(value.Summary),
		Findings: findings, CreatedAt: value.CreatedAt,
	}
}

func cloneNullableIntMap(values map[string]int) map[string]int {
	if values == nil {
		return nil
	}
	result := make(map[string]int, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func securityScanFromEvidenceContext(value evidencedomain.SecurityScan) domain.SecurityScan {
	return domain.SecurityScanFromContext(value)
}

func manualSecurityDocumentFromEvidenceContext(value evidencedomain.ManualSecurityDocument) domain.ManualSecurityDocument {
	return domain.ManualSecurityDocumentFromContext(value)
}

func sbomDiffFromEvidenceContext(value evidencedomain.SBOMDiff) domain.SBOMDiff {
	return domain.SBOMDiffFromContext(value)
}

func contractDiffFromEvidenceContext(value evidencedomain.ContractDiff) domain.ContractDiff {
	return domain.ContractDiffFromContext(value)
}

func lifecycleToEvidenceContext(value domain.EvidenceLifecycleEvent) (evidencedomain.EvidenceLifecycleEvent, error) {
	action, err := evidencedomain.ParseEvidenceLifecycleState(value.Action)
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, evidenceapp.ErrValidation
	}
	return evidencedomain.EvidenceLifecycleEvent{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Action: action,
		Reason: value.Reason, Details: cloneMap(value.Details), ReplacementID: value.ReplacementID,
		ActorID: value.ActorID, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}, nil
}

func lifecycleFromEvidenceContext(value evidencedomain.EvidenceLifecycleEvent) domain.EvidenceLifecycleEvent {
	return domain.EvidenceLifecycleEvent{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Action: value.Action.String(),
		Reason: value.Reason, Details: cloneMap(value.Details), ReplacementID: value.ReplacementID,
		ActorID: value.ActorID, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func objectPayloadToEvidenceContext(value ObjectPayload) evidenceapp.StagedPayload {
	return evidenceapp.StagedPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType, StagingKey: value.StagingKey,
		FinalKey: value.FinalKey, Status: string(value.Status), FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: value.FinalizedAt, FailedAt: value.FailedAt, OrphanedAt: value.OrphanedAt,
	}
}

func objectPayloadFromEvidenceContext(value evidenceapp.StagedPayload) ObjectPayload {
	return ObjectPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType, StagingKey: value.StagingKey,
		FinalKey: value.FinalKey, Status: ObjectPayloadStatus(value.Status), FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: value.FinalizedAt, FailedAt: value.FailedAt, OrphanedAt: value.OrphanedAt,
	}
}

func toEvidenceContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return evidenceapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return evidenceapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return evidenceapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return evidenceapp.ErrConflict
	default:
		return err
	}
}

func fromEvidenceContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, evidenceapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, evidenceapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, evidenceapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, evidenceapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}

func cloneEvidenceMap(values map[string]domain.EvidenceItem) map[string]domain.EvidenceItem {
	result := make(map[string]domain.EvidenceItem, len(values))
	for key, value := range values {
		result[key] = evidenceFromContext(evidenceToContext(value))
	}
	return result
}

func cloneSBOMMap(values map[string]domain.SBOM) map[string]domain.SBOM {
	result := make(map[string]domain.SBOM, len(values))
	for key, value := range values {
		result[key] = sbomFromEvidenceContext(sbomToEvidenceContext(value))
	}
	return result
}

func cloneVulnerabilityScanMap(values map[string]domain.VulnerabilityScan) map[string]domain.VulnerabilityScan {
	result := make(map[string]domain.VulnerabilityScan, len(values))
	for key, value := range values {
		result[key] = vulnerabilityScanFromEvidenceContext(vulnerabilityScanToEvidenceContext(value))
	}
	return result
}

func cloneVEXDocumentMap(values map[string]domain.VEXDocument) map[string]domain.VEXDocument {
	result := make(map[string]domain.VEXDocument, len(values))
	for key, value := range values {
		result[key] = vexDocumentFromEvidenceContext(vexDocumentToEvidenceContext(value))
	}
	return result
}

func cloneVEXImportReportMap(values map[string]domain.VEXImportReport) map[string]domain.VEXImportReport {
	result := make(map[string]domain.VEXImportReport, len(values))
	for key, value := range values {
		result[key] = vexImportReportFromEvidenceContext(vexImportReportToEvidenceContext(value))
	}
	return result
}

func cloneOpenAPIContractMap(values map[string]domain.OpenAPIContract) map[string]domain.OpenAPIContract {
	result := make(map[string]domain.OpenAPIContract, len(values))
	for key, value := range values {
		result[key] = openAPIContractFromEvidenceContext(openAPIContractToEvidenceContext(value))
	}
	return result
}

func cloneEvidenceLifecycleMap(values map[string]domain.EvidenceLifecycleEvent) map[string]domain.EvidenceLifecycleEvent {
	result := make(map[string]domain.EvidenceLifecycleEvent, len(values))
	for key, value := range values {
		value.Details = cloneMap(value.Details)
		result[key] = value
	}
	return result
}

func cloneSecurityScanMap(values map[string]domain.SecurityScan) map[string]domain.SecurityScan {
	result := make(map[string]domain.SecurityScan, len(values))
	for key, value := range values {
		value.Summary = cloneIntMap(value.Summary)
		result[key] = value
	}
	return result
}

func cloneManualSecurityDocumentMap(values map[string]domain.ManualSecurityDocument) map[string]domain.ManualSecurityDocument {
	result := make(map[string]domain.ManualSecurityDocument, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneSBOMDiffMap(values map[string]domain.SBOMDiff) map[string]domain.SBOMDiff {
	result := make(map[string]domain.SBOMDiff, len(values))
	for key, value := range values {
		value.AddedComponents = append([]domain.SBOMComponent(nil), value.AddedComponents...)
		value.RemovedComponents = append([]domain.SBOMComponent(nil), value.RemovedComponents...)
		value.DependencyChanges = append([]domain.DependencyChange(nil), value.DependencyChanges...)
		result[key] = value
	}
	return result
}

func cloneDependencyChangeMap(values map[string]domain.DependencyChange) map[string]domain.DependencyChange {
	result := make(map[string]domain.DependencyChange, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneContractDiffMap(values map[string]domain.ContractDiff) map[string]domain.ContractDiff {
	result := make(map[string]domain.ContractDiff, len(values))
	for key, value := range values {
		value.BreakingChanges = append([]string(nil), value.BreakingChanges...)
		value.NonBreakingChanges = append([]string(nil), value.NonBreakingChanges...)
		result[key] = value
	}
	return result
}
