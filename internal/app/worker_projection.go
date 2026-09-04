package app

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// refreshWorkerProjectionLocked merges worker-owned parser and decision
// projections into the compatibility read model. Callers hold l.mu so the
// validated snapshot is published atomically with respect to legacy readers.
func (l *Ledger) refreshWorkerProjectionLocked(ctx context.Context, tenantID string) error {
	projectionStore := l.workerProjections
	if repositories, ok := activeRepositories(ctx); ok && repositories.WorkerProjection != nil {
		projectionStore = repositories.WorkerProjection
	}
	if projectionStore == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ErrValidation
	}
	if tenant, ok := l.tenants[tenantID]; !ok || tenant.ID != tenantID {
		return ErrNotFound
	}

	projection, err := projectionStore.LoadWorkerProjection(ctx, tenantID)
	if err != nil {
		return err
	}

	sboms := cloneSBOMMap(l.sboms)
	scans := cloneVulnerabilityScanMap(l.scans)
	contracts := cloneOpenAPIContractMap(l.contracts)
	vexDocuments := cloneVEXDocumentMap(l.vexDocuments)
	vexReports := cloneVEXImportReportMap(l.vexImportReports)
	attestations := cloneReleaseBuildAttestationMap(l.attestations)
	decisions := cloneVulnerabilityDecisionMap(l.decisions)
	evidence := cloneEvidenceMap(l.evidence)
	chain := cloneAuditChainMap(l.chain)

	if err := l.mergeWorkerSBOMs(tenantID, projection.SBOMs, sboms); err != nil {
		return err
	}
	if err := l.mergeWorkerScans(tenantID, projection.Scans, scans); err != nil {
		return err
	}
	if err := l.mergeWorkerContracts(tenantID, projection.Contracts, contracts); err != nil {
		return err
	}
	if err := l.mergeWorkerVEXDocuments(tenantID, projection.VEXDocuments, vexDocuments); err != nil {
		return err
	}
	if err := l.mergeWorkerVEXReports(tenantID, projection.VEXImportReports, vexDocuments, vexReports); err != nil {
		return err
	}
	if err := l.mergeWorkerAttestations(tenantID, projection.BuildAttestations, attestations); err != nil {
		return err
	}
	if err := l.mergeWorkerDecisions(tenantID, projection.VulnerabilityDecisions, scans, sboms, vexDocuments, decisions); err != nil {
		return err
	}
	if err := mergeWorkerAuditChain(tenantID, projection.AuditChainEntries, chain); err != nil {
		return err
	}
	if err := l.mergeParserNormalizations(tenantID, projection.ParserNormalizations, evidence, chain); err != nil {
		return err
	}

	l.evidence = evidence
	l.sboms = sboms
	l.scans = scans
	l.contracts = contracts
	l.vexDocuments = vexDocuments
	l.vexImportReports = vexReports
	l.attestations = attestations
	l.decisions = decisions
	l.chain = chain
	return nil
}

func (l *Ledger) mergeWorkerSBOMs(tenantID string, values []domain.SBOM, target map[string]domain.SBOM) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "SBOM"); err != nil {
			return err
		}
		if !l.projectionEvidenceExactlyMatches(tenantID, value.EvidenceID, value.ReleaseID, value.ArtifactID, "") {
			return projectionConflict("SBOM relationship")
		}
		if value.Format == "" || value.CreatedAt.IsZero() || !validSBOMProjectionShape(value) {
			return projectionConflict("SBOM value")
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneSBOMValue(value)
			continue
		}
		merged, err := mergeProjectedSBOM(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "SBOM", seen, target, func(value domain.SBOM) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerScans(tenantID string, values []domain.VulnerabilityScan, target map[string]domain.VulnerabilityScan) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "vulnerability scan"); err != nil {
			return err
		}
		if !l.projectionEvidenceExactlyMatches(tenantID, value.EvidenceID, value.ReleaseID, "", "") || value.CreatedAt.IsZero() {
			return projectionConflict("vulnerability scan relationship")
		}
		if !validScanProjectionShape(value) {
			return projectionConflict("vulnerability scan parsed shape")
		}
		findingIDs := make(map[string]struct{}, len(value.Findings))
		for _, finding := range value.Findings {
			if finding.ID == "" || finding.Vulnerability == "" {
				return projectionConflict("vulnerability finding value")
			}
			if _, duplicate := findingIDs[finding.ID]; duplicate {
				return projectionConflict("duplicate vulnerability finding")
			}
			findingIDs[finding.ID] = struct{}{}
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneVulnerabilityScanValue(value)
			continue
		}
		merged, err := mergeProjectedScan(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "vulnerability scan", seen, target, func(value domain.VulnerabilityScan) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerContracts(tenantID string, values []domain.OpenAPIContract, target map[string]domain.OpenAPIContract) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "OpenAPI contract"); err != nil {
			return err
		}
		product, productOK := l.products[value.ProductID]
		if !productOK || product.TenantID != tenantID || !l.projectionEvidenceExactlyMatches(tenantID, value.EvidenceID, value.ReleaseID, "", value.ProductID) || value.Version == "" || value.Hash == "" || value.CreatedAt.IsZero() || value.PathCount < 0 {
			return projectionConflict("OpenAPI contract relationship")
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneOpenAPIContractValue(value)
			continue
		}
		merged, err := mergeProjectedContract(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "OpenAPI contract", seen, target, func(value domain.OpenAPIContract) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerVEXDocuments(tenantID string, values []domain.VEXDocument, target map[string]domain.VEXDocument) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "VEX document"); err != nil {
			return err
		}
		if !l.projectionEvidenceExactlyMatches(tenantID, value.EvidenceID, value.ReleaseID, value.ArtifactID, "") || value.Format == "" || value.SchemaVersion == "" || value.CreatedAt.IsZero() || value.StatementCount < 0 {
			return projectionConflict("VEX document relationship")
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneVEXDocumentValue(value)
			continue
		}
		merged, err := mergeProjectedVEXDocument(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "VEX document", seen, target, func(value domain.VEXDocument) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerVEXReports(tenantID string, values []domain.VEXImportReport, documents map[string]domain.VEXDocument, target map[string]domain.VEXImportReport) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "VEX import report"); err != nil {
			return err
		}
		document, ok := documents[value.VEXDocumentID]
		if !ok || document.TenantID != tenantID || document.EvidenceID != value.EvidenceID || document.ReleaseID != value.ReleaseID || document.ArtifactID != value.ArtifactID || value.ParserVersion == "" || value.SchemaVersion == "" || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || (value.Status == "accepted" && value.UpdatedAt.Before(value.CreatedAt)) || value.StatementCount < 0 || value.DecisionsCreated < 0 || value.DecisionsSuperseded < 0 || !validVEXReportStatus(value.Status) {
			return projectionConflict("VEX import report relationship")
		}
		existing, exists := target[value.ID]
		if !exists {
			if value.UpdatedAt.Before(value.CreatedAt) {
				value.UpdatedAt = value.CreatedAt
			}
			target[value.ID] = cloneVEXImportReportValue(value)
			continue
		}
		merged, err := mergeProjectedVEXReport(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "VEX import report", seen, target, func(value domain.VEXImportReport) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerAttestations(tenantID string, values []domain.BuildAttestation, target map[string]domain.BuildAttestation) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "build attestation"); err != nil {
			return err
		}
		build, buildOK := l.buildRuns[value.BuildID]
		evidence, evidenceOK := l.evidence[value.EvidenceID]
		if !buildOK || build.TenantID != tenantID || !evidenceOK || evidence.TenantID != tenantID || evidence.BuildID != value.BuildID || value.SchemaVersion == "" || value.CreatedAt.IsZero() || !validBuildAttestationProjectionShape(value) {
			return projectionConflict("build attestation relationship")
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneBuildAttestationValue(value)
			continue
		}
		merged, err := mergeProjectedBuildAttestation(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	return requireAuthoritativeProjectionRows(tenantID, "build attestation", seen, target, func(value domain.BuildAttestation) string { return value.TenantID })
}

func (l *Ledger) mergeWorkerDecisions(tenantID string, values []domain.VulnerabilityDecision, scans map[string]domain.VulnerabilityScan, sboms map[string]domain.SBOM, documents map[string]domain.VEXDocument, target map[string]domain.VulnerabilityDecision) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validProjectionIdentity(tenantID, value.ID, value.TenantID, seen, "vulnerability decision"); err != nil {
			return err
		}
		if err := l.validateProjectedDecision(tenantID, value, scans, sboms, documents); err != nil {
			return err
		}
		existing, ok := target[value.ID]
		if !ok {
			target[value.ID] = cloneVulnerabilityDecisionValue(value)
			continue
		}
		merged, err := mergeProjectedDecision(existing, value)
		if err != nil {
			return err
		}
		target[value.ID] = merged
	}
	for _, value := range target {
		if value.TenantID != tenantID {
			continue
		}
		if value.Supersedes != "" {
			previous, ok := target[value.Supersedes]
			if !ok || previous.TenantID != tenantID || previous.SupersededBy != value.ID {
				return projectionConflict("vulnerability decision supersession")
			}
		}
		if value.SupersededBy != "" {
			replacement, ok := target[value.SupersededBy]
			if !ok || replacement.TenantID != tenantID || replacement.Supersedes != value.ID {
				return projectionConflict("vulnerability decision replacement")
			}
		}
	}
	return requireAuthoritativeProjectionRows(tenantID, "vulnerability decision", seen, target, func(value domain.VulnerabilityDecision) string { return value.TenantID })
}

func (l *Ledger) validateProjectedDecision(tenantID string, value domain.VulnerabilityDecision, scans map[string]domain.VulnerabilityScan, sboms map[string]domain.SBOM, documents map[string]domain.VEXDocument) error {
	if value.FindingID == "" || value.ScanID == "" || value.Vulnerability == "" || value.Status == "" || value.Justification == "" || value.Source == "" || value.SchemaVersion == "" || value.CreatedAt.IsZero() {
		return projectionConflict("vulnerability decision value")
	}
	scan, ok := scans[value.ScanID]
	if !ok || scan.TenantID != tenantID || scan.ReleaseID != value.ReleaseID {
		return projectionConflict("vulnerability decision scan")
	}
	findingOK := false
	for _, finding := range scan.Findings {
		if finding.ID == value.FindingID && finding.Vulnerability == value.Vulnerability && finding.Component == value.Component {
			findingOK = true
			break
		}
	}
	if !findingOK {
		return projectionConflict("vulnerability decision finding")
	}
	if value.SBOMID != "" {
		sbom, ok := sboms[value.SBOMID]
		if !ok || sbom.TenantID != tenantID || sbom.ReleaseID != value.ReleaseID {
			return projectionConflict("vulnerability decision SBOM")
		}
	}
	if value.VEXDocumentID != "" {
		document, ok := documents[value.VEXDocumentID]
		if !ok || document.TenantID != tenantID || document.ReleaseID != value.ReleaseID || (value.EvidenceID != "" && document.EvidenceID != value.EvidenceID) {
			return projectionConflict("vulnerability decision VEX document")
		}
	}
	if value.EvidenceID != "" && !l.projectionDecisionPrimaryEvidenceMatches(tenantID, value.EvidenceID, value.ReleaseID) {
		return projectionConflict("vulnerability decision evidence")
	}
	for _, evidenceID := range value.EvidenceIDs {
		if !l.projectionDecisionEvidenceMatches(tenantID, evidenceID, value.ReleaseID) {
			return projectionConflict("vulnerability decision supporting evidence")
		}
	}
	return nil
}

func (l *Ledger) projectionDecisionPrimaryEvidenceMatches(tenantID, evidenceID, releaseID string) bool {
	evidence, ok := l.evidence[evidenceID]
	return ok && evidence.TenantID == tenantID && evidence.ReleaseID == releaseID
}

func (l *Ledger) projectionDecisionEvidenceMatches(tenantID, evidenceID, releaseID string) bool {
	evidence, ok := l.evidence[evidenceID]
	return ok && evidence.TenantID == tenantID && (evidence.ReleaseID == "" || evidence.ReleaseID == releaseID)
}

func (l *Ledger) projectionEvidenceExactlyMatches(tenantID, evidenceID, releaseID, artifactID, productID string) bool {
	evidence, ok := l.evidence[evidenceID]
	if !ok || evidence.TenantID != tenantID || evidence.ReleaseID != releaseID {
		return false
	}
	if releaseID != "" {
		release, ok := l.releases[releaseID]
		if !ok || release.TenantID != tenantID {
			return false
		}
	}
	if productID != "" {
		product, ok := l.products[productID]
		if !ok || product.TenantID != tenantID || evidence.ProductID != productID {
			return false
		}
	}
	artifactIDs := make(map[string]struct{})
	for _, ref := range evidence.SubjectRefs {
		if ref.Type == "artifact" && ref.ID != "" {
			artifactIDs[ref.ID] = struct{}{}
		}
	}
	if artifactID == "" {
		return len(artifactIDs) == 0
	}
	artifact, ok := l.artifacts[artifactID]
	if !ok || artifact.TenantID != tenantID || len(artifactIDs) != 1 {
		return false
	}
	_, ok = artifactIDs[artifactID]
	return ok
}

func mergeWorkerAuditChain(tenantID string, incoming []domain.AuditChainEntry, target map[string][]domain.AuditChainEntry) error {
	existing := target[tenantID]
	if len(incoming) < len(existing) {
		return projectionConflict("audit chain shrink")
	}
	if len(incoming) == 0 {
		return nil
	}
	seenIDs := make(map[string]struct{}, len(incoming))
	previousHash := ""
	for index, entry := range incoming {
		if entry.ID == "" || entry.TenantID != tenantID || entry.Sequence != int64(index+1) || entry.PreviousEntryHash != previousHash {
			return projectionConflict("audit chain sequence")
		}
		if _, duplicate := seenIDs[entry.ID]; duplicate {
			return projectionConflict("duplicate audit chain entry")
		}
		seenIDs[entry.ID] = struct{}{}
		canonical, valid, err := verifiedAuditChainCanonicalHash(entry)
		if err != nil || !valid || entry.EntryHash != hashBytes([]byte(entry.PreviousEntryHash+"\n"+canonical)) {
			return projectionConflict("audit chain hash")
		}
		previousHash = entry.EntryHash
	}
	common := len(existing)
	if len(incoming) < common {
		common = len(incoming)
	}
	for index := 0; index < common; index++ {
		if existing[index].ID != incoming[index].ID || existing[index].Sequence != incoming[index].Sequence || existing[index].CanonicalEntryHash != incoming[index].CanonicalEntryHash || existing[index].EntryHash != incoming[index].EntryHash {
			return projectionConflict("audit chain divergence")
		}
	}
	if len(incoming) > len(existing) {
		cloned, err := cloneAuditChain(map[string][]domain.AuditChainEntry{tenantID: incoming})
		if err != nil {
			return err
		}
		target[tenantID] = cloned[tenantID]
	}
	return nil
}

func validProjectionIdentity(tenantID, id, rowTenantID string, seen map[string]struct{}, kind string) error {
	if id == "" || strings.TrimSpace(id) != id || rowTenantID != tenantID {
		return projectionConflict(kind + " identity")
	}
	if _, duplicate := seen[id]; duplicate {
		return projectionConflict("duplicate " + kind)
	}
	seen[id] = struct{}{}
	return nil
}

func requireAuthoritativeProjectionRows[T any](tenantID, kind string, seen map[string]struct{}, target map[string]T, tenantOf func(T) string) error {
	for id, value := range target {
		if tenantOf(value) != tenantID {
			continue
		}
		if _, ok := seen[id]; !ok {
			return projectionConflict(kind + " row shrink")
		}
	}
	return nil
}

func projectionConflict(subject string) error {
	return fmt.Errorf("invalid worker projection %s: %w", subject, ErrConflict)
}

func mergeProjectedSBOM(existing, incoming domain.SBOM) (domain.SBOM, error) {
	if !validSBOMProjectionShape(existing) || !validSBOMProjectionShape(incoming) {
		return domain.SBOM{}, projectionConflict("SBOM parsed shape")
	}
	left, right := existing, incoming
	left.SpecVersion, right.SpecVersion = "", ""
	left.ComponentCount, right.ComponentCount = 0, 0
	left.Components, right.Components = nil, nil
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || !reflect.DeepEqual(left, right) {
		return domain.SBOM{}, projectionConflict("SBOM immutable fields")
	}
	if err := hydrateString(&existing.SpecVersion, incoming.SpecVersion); err != nil {
		return domain.SBOM{}, projectionConflict("SBOM spec version")
	}
	if err := hydrateInt(&existing.ComponentCount, incoming.ComponentCount); err != nil {
		return domain.SBOM{}, projectionConflict("SBOM component count")
	}
	if err := hydrateSlice(&existing.Components, incoming.Components); err != nil {
		return domain.SBOM{}, projectionConflict("SBOM components")
	}
	return cloneSBOMValue(existing), nil
}

func validSBOMProjectionShape(value domain.SBOM) bool {
	if value.ComponentCount < 0 {
		return false
	}
	if value.SpecVersion == "" {
		return value.ComponentCount == 0 && len(value.Components) == 0
	}
	return value.ComponentCount == len(value.Components)
}

func mergeProjectedScan(existing, incoming domain.VulnerabilityScan) (domain.VulnerabilityScan, error) {
	if !validScanProjectionShape(existing) || !validScanProjectionShape(incoming) {
		return domain.VulnerabilityScan{}, projectionConflict("vulnerability scan parsed shape")
	}
	left, right := existing, incoming
	left.Scanner, right.Scanner = "", ""
	left.Adapter, right.Adapter = "", ""
	left.AdapterVersion, right.AdapterVersion = "", ""
	left.SourceSchema, right.SourceSchema = "", ""
	left.TargetRef, right.TargetRef = "", ""
	left.Summary, right.Summary = nil, nil
	left.Findings, right.Findings = nil, nil
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || !reflect.DeepEqual(left, right) {
		return domain.VulnerabilityScan{}, projectionConflict("vulnerability scan immutable fields")
	}
	for _, pair := range []struct {
		target *string
		value  string
	}{{&existing.Scanner, incoming.Scanner}, {&existing.Adapter, incoming.Adapter}, {&existing.AdapterVersion, incoming.AdapterVersion}, {&existing.SourceSchema, incoming.SourceSchema}, {&existing.TargetRef, incoming.TargetRef}} {
		if err := hydrateString(pair.target, pair.value); err != nil {
			return domain.VulnerabilityScan{}, projectionConflict("vulnerability scan parsed field")
		}
	}
	if err := hydrateMap(&existing.Summary, incoming.Summary); err != nil {
		return domain.VulnerabilityScan{}, projectionConflict("vulnerability scan summary")
	}
	if err := hydrateSlice(&existing.Findings, incoming.Findings); err != nil {
		return domain.VulnerabilityScan{}, projectionConflict("vulnerability scan findings")
	}
	return cloneVulnerabilityScanValue(existing), nil
}

func validScanProjectionShape(value domain.VulnerabilityScan) bool {
	parsedFields := []string{value.Scanner, value.Adapter, value.AdapterVersion, value.SourceSchema, value.TargetRef}
	present := 0
	for _, field := range parsedFields {
		if field != "" {
			present++
		}
	}
	if present == 0 {
		return len(value.Summary) == 0 && len(value.Findings) == 0
	}
	return present == len(parsedFields)
}

func mergeProjectedContract(existing, incoming domain.OpenAPIContract) (domain.OpenAPIContract, error) {
	left, right := existing, incoming
	left.PathCount, right.PathCount = 0, 0
	left.Operations, right.Operations = nil, nil
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || !reflect.DeepEqual(left, right) {
		return domain.OpenAPIContract{}, projectionConflict("OpenAPI contract immutable fields")
	}
	if err := hydrateInt(&existing.PathCount, incoming.PathCount); err != nil {
		return domain.OpenAPIContract{}, projectionConflict("OpenAPI contract path count")
	}
	if err := hydrateSlice(&existing.Operations, incoming.Operations); err != nil {
		return domain.OpenAPIContract{}, projectionConflict("OpenAPI contract operations")
	}
	return cloneOpenAPIContractValue(existing), nil
}

func mergeProjectedVEXDocument(existing, incoming domain.VEXDocument) (domain.VEXDocument, error) {
	left, right := existing, incoming
	left.Author, right.Author = "", ""
	left.StatementCount, right.StatementCount = 0, 0
	left.StatusSummary, right.StatusSummary = nil, nil
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || !reflect.DeepEqual(left, right) {
		return domain.VEXDocument{}, projectionConflict("VEX document immutable fields")
	}
	if err := hydrateString(&existing.Author, incoming.Author); err != nil {
		return domain.VEXDocument{}, projectionConflict("VEX document author")
	}
	if err := hydrateInt(&existing.StatementCount, incoming.StatementCount); err != nil {
		return domain.VEXDocument{}, projectionConflict("VEX document statement count")
	}
	if err := hydrateMap(&existing.StatusSummary, incoming.StatusSummary); err != nil {
		return domain.VEXDocument{}, projectionConflict("VEX document status summary")
	}
	return cloneVEXDocumentValue(existing), nil
}

func mergeProjectedVEXReport(existing, incoming domain.VEXImportReport) (domain.VEXImportReport, error) {
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || existing.ID != incoming.ID || existing.TenantID != incoming.TenantID || existing.VEXDocumentID != incoming.VEXDocumentID || existing.EvidenceID != incoming.EvidenceID || existing.ReleaseID != incoming.ReleaseID || existing.ArtifactID != incoming.ArtifactID || existing.ParserVersion != incoming.ParserVersion {
		return domain.VEXImportReport{}, projectionConflict("VEX import report immutable fields")
	}
	if !validVEXReportStatus(existing.Status) || !validVEXReportStatus(incoming.Status) || !validVEXReportTransition(existing.Status, incoming.Status) {
		return domain.VEXImportReport{}, projectionConflict("VEX import report status regression")
	}
	if existing.Status == incoming.Status {
		if existing.Status == "failed" {
			left, right := existing, incoming
			left.FailureCode, right.FailureCode = "", ""
			left.FailureDetail, right.FailureDetail = "", ""
			left.SchemaVersion, right.SchemaVersion = "", ""
			if !sameVEXImportReport(left, right, true) {
				return domain.VEXImportReport{}, projectionConflict("VEX import report failed-state mutation")
			}
		} else if !sameVEXImportReport(existing, incoming, true) {
			return domain.VEXImportReport{}, projectionConflict("VEX import report same-status mutation")
		}
	}
	// Status progression is authoritative. The API and worker can run with
	// skewed wall clocks, so UpdatedAt cannot decide whether accepted became
	// failed/parsed or failed became parsed. Preserve a monotonic presentation
	// timestamp while publishing the durable terminal state.
	if incoming.UpdatedAt.Before(existing.UpdatedAt) {
		incoming.UpdatedAt = existing.UpdatedAt
	}
	if incoming.UpdatedAt.Before(incoming.CreatedAt) {
		incoming.UpdatedAt = incoming.CreatedAt
	}
	return cloneVEXImportReportValue(incoming), nil
}

func sameVEXImportReport(left, right domain.VEXImportReport, ignoreUpdatedAt bool) bool {
	if !samePersistedTime(left.CreatedAt, right.CreatedAt) || (!ignoreUpdatedAt && !samePersistedTime(left.UpdatedAt, right.UpdatedAt)) {
		return false
	}
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	left.UpdatedAt, right.UpdatedAt = time.Time{}, time.Time{}
	if len(left.UnsupportedFields) == 0 {
		left.UnsupportedFields = nil
	}
	if len(right.UnsupportedFields) == 0 {
		right.UnsupportedFields = nil
	}
	if len(left.Warnings) == 0 {
		left.Warnings = nil
	}
	if len(right.Warnings) == 0 {
		right.Warnings = nil
	}
	if len(left.InvalidStatements) == 0 {
		left.InvalidStatements = nil
	}
	if len(right.InvalidStatements) == 0 {
		right.InvalidStatements = nil
	}
	if len(left.MappingFailures) == 0 {
		left.MappingFailures = nil
	}
	if len(right.MappingFailures) == 0 {
		right.MappingFailures = nil
	}
	return reflect.DeepEqual(left, right)
}

func mergeProjectedBuildAttestation(existing, incoming domain.BuildAttestation) (domain.BuildAttestation, error) {
	if !validBuildAttestationProjectionShape(existing) || !validBuildAttestationProjectionShape(incoming) {
		return domain.BuildAttestation{}, projectionConflict("build attestation parsed shape")
	}
	left, right := existing, incoming
	left.PayloadType, right.PayloadType = "", ""
	left.PredicateType, right.PredicateType = "", ""
	left.SubjectDigests, right.SubjectDigests = nil, nil
	left.BuilderID, right.BuilderID = "", ""
	left.BuildType, right.BuildType = "", ""
	left.MaterialsCount, right.MaterialsCount = 0, 0
	left.SignatureCount, right.SignatureCount = 0, 0
	left.VerificationStatus, right.VerificationStatus = "", ""
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	if !samePersistedTime(existing.CreatedAt, incoming.CreatedAt) || !reflect.DeepEqual(left, right) {
		return domain.BuildAttestation{}, projectionConflict("build attestation immutable fields")
	}
	for _, pair := range []struct {
		target *string
		value  string
	}{{&existing.PayloadHash, incoming.PayloadHash}, {&existing.PayloadType, incoming.PayloadType}, {&existing.PredicateType, incoming.PredicateType}, {&existing.BuilderID, incoming.BuilderID}, {&existing.BuildType, incoming.BuildType}} {
		if err := hydrateString(pair.target, pair.value); err != nil {
			return domain.BuildAttestation{}, projectionConflict("build attestation parsed field")
		}
	}
	if err := hydrateInt(&existing.MaterialsCount, incoming.MaterialsCount); err != nil {
		return domain.BuildAttestation{}, projectionConflict("build attestation materials count")
	}
	if err := hydrateInt(&existing.SignatureCount, incoming.SignatureCount); err != nil {
		return domain.BuildAttestation{}, projectionConflict("build attestation signature count")
	}
	if err := hydrateSlice(&existing.SubjectDigests, incoming.SubjectDigests); err != nil {
		return domain.BuildAttestation{}, projectionConflict("build attestation subject digests")
	}
	if existing.VerificationStatus == "" {
		existing.VerificationStatus = incoming.VerificationStatus
	} else if incoming.VerificationStatus != "" && incoming.VerificationStatus != existing.VerificationStatus {
		if existing.VerificationStatus != "accepted" || incoming.VerificationStatus != "structurally_valid" {
			return domain.BuildAttestation{}, projectionConflict("build attestation verification status")
		}
		existing.VerificationStatus = incoming.VerificationStatus
	}
	return cloneBuildAttestationValue(existing), nil
}

func validBuildAttestationProjectionShape(value domain.BuildAttestation) bool {
	if value.PayloadSize < 0 || value.MaterialsCount < 0 || value.SignatureCount < 0 {
		return false
	}
	parsedFieldsEmpty := value.PayloadType == "" && value.PredicateType == "" && len(value.SubjectDigests) == 0 && value.BuilderID == "" && value.BuildType == "" && value.MaterialsCount == 0 && value.SignatureCount == 0
	switch value.VerificationStatus {
	case "accepted":
		return parsedFieldsEmpty
	case "structurally_valid":
		return value.PayloadType != "" && value.PredicateType != ""
	default:
		return false
	}
}

func mergeProjectedDecision(existing, incoming domain.VulnerabilityDecision) (domain.VulnerabilityDecision, error) {
	left, right := existing, incoming
	left.SupersededBy, right.SupersededBy = "", ""
	left = normalizedProjectedDecision(left)
	right = normalizedProjectedDecision(right)
	if !reflect.DeepEqual(left, right) {
		return domain.VulnerabilityDecision{}, projectionConflict("vulnerability decision immutable fields")
	}
	if existing.SupersededBy == "" {
		existing.SupersededBy = incoming.SupersededBy
	} else if incoming.SupersededBy != existing.SupersededBy {
		return domain.VulnerabilityDecision{}, projectionConflict("vulnerability decision superseded-by")
	}
	return cloneVulnerabilityDecisionValue(existing), nil
}

func normalizedProjectedDecision(value domain.VulnerabilityDecision) domain.VulnerabilityDecision {
	value.CreatedAt = value.CreatedAt.UTC().Truncate(time.Microsecond)
	if value.ReviewedAt != nil {
		reviewedAt := value.ReviewedAt.UTC().Truncate(time.Microsecond)
		value.ReviewedAt = &reviewedAt
	}
	if value.ReviewDueAt != nil {
		reviewDueAt := value.ReviewDueAt.UTC().Truncate(time.Microsecond)
		value.ReviewDueAt = &reviewDueAt
	}
	if len(value.EvidenceIDs) == 0 {
		value.EvidenceIDs = nil
	}
	if len(value.SupportingRefs) == 0 {
		value.SupportingRefs = nil
	}
	return value
}

func hydrateString(target *string, value string) error {
	if *target == value {
		return nil
	}
	if *target == "" {
		*target = value
		return nil
	}
	if *target != value {
		return ErrConflict
	}
	return nil
}

func hydrateInt(target *int, value int) error {
	if *target == value {
		return nil
	}
	if *target == 0 {
		*target = value
		return nil
	}
	if *target != value {
		return ErrConflict
	}
	return nil
}

func hydrateSlice[T any](target *[]T, value []T) error {
	if len(*target) == 0 && len(value) == 0 {
		return nil
	}
	if len(*target) == 0 {
		*target = append([]T(nil), value...)
		return nil
	}
	if !reflect.DeepEqual(*target, value) {
		return ErrConflict
	}
	return nil
}

func hydrateMap[K comparable, V any](target *map[K]V, value map[K]V) error {
	if len(*target) == 0 && len(value) == 0 {
		return nil
	}
	if len(*target) == 0 {
		cloned := make(map[K]V, len(value))
		for key, item := range value {
			cloned[key] = item
		}
		*target = cloned
		return nil
	}
	if !reflect.DeepEqual(*target, value) {
		return ErrConflict
	}
	return nil
}

func validVEXReportStatus(status string) bool {
	return status == "accepted" || status == "failed" || status == "parsed"
}

func validVEXReportTransition(from, to string) bool {
	switch from {
	case "accepted":
		return to == "accepted" || to == "failed" || to == "parsed"
	case "failed":
		return to == "failed" || to == "parsed"
	case "parsed":
		return to == "parsed"
	default:
		return false
	}
}

func cloneSBOMValue(value domain.SBOM) domain.SBOM {
	return cloneSBOMMap(map[string]domain.SBOM{value.ID: value})[value.ID]
}

func cloneVulnerabilityScanValue(value domain.VulnerabilityScan) domain.VulnerabilityScan {
	return cloneVulnerabilityScanMap(map[string]domain.VulnerabilityScan{value.ID: value})[value.ID]
}

func cloneOpenAPIContractValue(value domain.OpenAPIContract) domain.OpenAPIContract {
	return cloneOpenAPIContractMap(map[string]domain.OpenAPIContract{value.ID: value})[value.ID]
}

func cloneVEXDocumentValue(value domain.VEXDocument) domain.VEXDocument {
	return cloneVEXDocumentMap(map[string]domain.VEXDocument{value.ID: value})[value.ID]
}

func cloneVEXImportReportValue(value domain.VEXImportReport) domain.VEXImportReport {
	return cloneVEXImportReportMap(map[string]domain.VEXImportReport{value.ID: value})[value.ID]
}

func cloneBuildAttestationValue(value domain.BuildAttestation) domain.BuildAttestation {
	return cloneReleaseBuildAttestationMap(map[string]domain.BuildAttestation{value.ID: value})[value.ID]
}

func cloneVulnerabilityDecisionValue(value domain.VulnerabilityDecision) domain.VulnerabilityDecision {
	return cloneVulnerabilityDecisionMap(map[string]domain.VulnerabilityDecision{value.ID: value})[value.ID]
}
