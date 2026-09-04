package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

var _ app.WorkerProjectionStore = (*Store)(nil)
var _ app.WorkerProjectionStore = transactionWorkerProjectionStore{}

type transactionWorkerProjectionStore struct{ tx pgx.Tx }

func (s transactionWorkerProjectionStore) LoadWorkerProjection(ctx context.Context, tenantID string) (app.WorkerProjection, error) {
	return loadWorkerProjection(ctx, s.tx, tenantID, true)
}

// LoadWorkerProjection returns one tenant's worker-owned read model from a
// single, stable database snapshot. Every query keeps tenant ownership in its
// SQL predicate rather than relying on filtering after rows are loaded.
func (s *Store) LoadWorkerProjection(ctx context.Context, tenantID string) (app.WorkerProjection, error) {
	if ctx == nil || s == nil || s.pool == nil || strings.TrimSpace(tenantID) == "" {
		return app.WorkerProjection{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.WorkerProjection{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return app.WorkerProjection{}, fmt.Errorf("begin worker projection transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	projection, err := loadWorkerProjection(ctx, tx, tenantID, false)
	if err != nil {
		return app.WorkerProjection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.WorkerProjection{}, fmt.Errorf("commit worker projection transaction: %w", err)
	}
	return projection, nil
}

func loadWorkerProjection(ctx context.Context, tx pgx.Tx, tenantID string, exclusive bool) (app.WorkerProjection, error) {
	if ctx == nil || tx == nil || strings.TrimSpace(tenantID) == "" {
		return app.WorkerProjection{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.WorkerProjection{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	lock := coordination.LockWorkerProjectionShared
	if exclusive {
		lock = coordination.LockWorkerProjection
	}
	if err := lock(ctx, tx, tenantID); err != nil {
		return app.WorkerProjection{}, fmt.Errorf("lock tenant worker projection: %w", err)
	}

	var projection app.WorkerProjection
	loaders := []func(context.Context, pgx.Tx, string, *app.WorkerProjection) error{
		loadWorkerProjectionParserNormalizations,
		loadWorkerProjectionSBOMs,
		loadWorkerProjectionScans,
		loadWorkerProjectionContracts,
		loadWorkerProjectionVEXDocuments,
		loadWorkerProjectionVEXImportReports,
		loadWorkerProjectionBuildAttestations,
		loadWorkerProjectionVulnerabilityDecisions,
		loadWorkerProjectionAuditChain,
	}
	for _, load := range loaders {
		if err := load(ctx, tx, tenantID, &projection); err != nil {
			return app.WorkerProjection{}, err
		}
	}
	return projection, nil
}

func lockWorkerProjectionMutation(ctx context.Context, tx pgx.Tx, mutation app.ReleaseLedgerMutation) error {
	return lockWorkerProjectionTenantIDs(ctx, tx, releaseLedgerMutationTenantIDs(mutation))
}

func lockCriticalProjectionMutation(ctx context.Context, tx pgx.Tx, mutation app.CriticalMutation) error {
	tenantIDs := []string{}
	for _, value := range mutation.Tenants {
		tenantIDs = append(tenantIDs, value.ID)
	}
	for _, value := range mutation.APIKeys {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.Collectors {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.SSOSessions {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.CustomerPortalAccess {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.SigningKeys {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.Signatures {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.ReleaseBundles {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.VerificationResults {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.ProviderVerifications {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.VulnerabilityDecisions {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.AuditChainEntries {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	for _, value := range mutation.OutboxJobs {
		tenantIDs = append(tenantIDs, value.TenantID)
	}
	return lockWorkerProjectionTenantIDs(ctx, tx, tenantIDs)
}

func lockPersistedStateProjectionMutations(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	tenantIDs := make([]string, 0, len(state.Tenants)+len(state.Chain))
	for tenantID := range state.Tenants {
		tenantIDs = append(tenantIDs, tenantID)
	}
	for tenantID := range state.Chain {
		tenantIDs = append(tenantIDs, tenantID)
	}
	return lockWorkerProjectionTenantIDs(ctx, tx, tenantIDs)
}

func lockWorkerProjectionTenantIDs(ctx context.Context, tx pgx.Tx, tenantIDs []string) error {
	seen := make(map[string]struct{}, len(tenantIDs))
	ordered := make([]string, 0, len(tenantIDs))
	for _, tenantID := range tenantIDs {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			continue
		}
		if _, ok := seen[tenantID]; ok {
			continue
		}
		seen[tenantID] = struct{}{}
		ordered = append(ordered, tenantID)
	}
	sort.Strings(ordered)
	for _, tenantID := range ordered {
		if err := coordination.LockWorkerProjection(ctx, tx, tenantID); err != nil {
			return fmt.Errorf("lock tenant worker projection mutation: %w", err)
		}
	}
	return nil
}

func releaseLedgerMutationTenantIDs(mutation app.ReleaseLedgerMutation) []string {
	seen := map[string]struct{}{}
	add := func(tenantID string) {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID != "" {
			seen[tenantID] = struct{}{}
		}
	}
	for _, value := range mutation.Products {
		add(value.TenantID)
	}
	for _, value := range mutation.Projects {
		add(value.TenantID)
	}
	for _, value := range mutation.Releases {
		add(value.TenantID)
	}
	for _, value := range mutation.Artifacts {
		add(value.TenantID)
	}
	for _, value := range mutation.Evidence {
		add(value.TenantID)
	}
	for _, value := range mutation.EvidenceLifecycle {
		add(value.TenantID)
	}
	for _, value := range mutation.SBOMs {
		add(value.TenantID)
	}
	for _, value := range mutation.Scans {
		add(value.TenantID)
	}
	for _, value := range mutation.Contracts {
		add(value.TenantID)
	}
	for _, value := range mutation.VEXDocuments {
		add(value.TenantID)
	}
	for _, value := range mutation.VEXImportReports {
		add(value.TenantID)
	}
	for _, value := range mutation.BuildAttestations {
		add(value.TenantID)
	}
	for _, value := range mutation.VulnerabilityDecisions {
		add(value.TenantID)
	}
	for _, value := range mutation.AuditChainEntries {
		add(value.TenantID)
	}
	for _, value := range mutation.OutboxJobs {
		add(value.TenantID)
	}
	tenantIDs := make([]string, 0, len(seen))
	for tenantID := range seen {
		tenantIDs = append(tenantIDs, tenantID)
	}
	sort.Strings(tenantIDs)
	return tenantIDs
}

func loadWorkerProjectionSBOMs(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, evidence_id, release_id, artifact_id, format,
		       spec_version, component_count, components, created_at
		FROM sboms
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection sboms: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sbom domain.SBOM
		var releaseID, artifactID sql.NullString
		var components []byte
		if err := rows.Scan(
			&sbom.ID, &sbom.TenantID, &sbom.EvidenceID, &releaseID, &artifactID, &sbom.Format,
			&sbom.SpecVersion, &sbom.ComponentCount, &components, &sbom.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection sbom: %w", err)
		}
		sbom.ReleaseID = nullableSQLString(releaseID)
		sbom.ArtifactID = nullableSQLString(artifactID)
		if err := decodeJSON(components, &sbom.Components); err != nil {
			return fmt.Errorf("decode worker projection sbom components: %w", err)
		}
		projection.SBOMs = append(projection.SBOMs, sbom)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection sboms: %w", err)
	}
	return nil
}

func loadWorkerProjectionScans(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, evidence_id, release_id, scanner, adapter,
		       adapter_version, source_schema, target_ref, summary, findings, created_at
		FROM vulnerability_scans
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection vulnerability scans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var scan domain.VulnerabilityScan
		var releaseID sql.NullString
		var summary, findings []byte
		if err := rows.Scan(
			&scan.ID, &scan.TenantID, &scan.EvidenceID, &releaseID, &scan.Scanner, &scan.Adapter,
			&scan.AdapterVersion, &scan.SourceSchema, &scan.TargetRef, &summary, &findings, &scan.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection vulnerability scan: %w", err)
		}
		scan.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(summary, &scan.Summary); err != nil {
			return fmt.Errorf("decode worker projection vulnerability scan summary: %w", err)
		}
		if err := decodeJSON(findings, &scan.Findings); err != nil {
			return fmt.Errorf("decode worker projection vulnerability scan findings: %w", err)
		}
		projection.Scans = append(projection.Scans, scan)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection vulnerability scans: %w", err)
	}
	return nil
}

func loadWorkerProjectionContracts(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, product_id, release_id, version, hash, path_count,
		       operations, evidence_id, created_at
		FROM openapi_contracts
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection openapi contracts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var contract domain.OpenAPIContract
		var releaseID sql.NullString
		var operations []byte
		if err := rows.Scan(
			&contract.ID, &contract.TenantID, &contract.ProductID, &releaseID, &contract.Version,
			&contract.Hash, &contract.PathCount, &operations, &contract.EvidenceID, &contract.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection openapi contract: %w", err)
		}
		contract.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(operations, &contract.Operations); err != nil {
			return fmt.Errorf("decode worker projection openapi operations: %w", err)
		}
		projection.Contracts = append(projection.Contracts, contract)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection openapi contracts: %w", err)
	}
	return nil
}

func loadWorkerProjectionVEXDocuments(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, evidence_id, release_id, artifact_id, format, author,
		       version, statement_count, status_summary, schema_version, created_at
		FROM vex_documents
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection vex documents: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var document domain.VEXDocument
		var releaseID, artifactID, version sql.NullString
		var statusSummary []byte
		if err := rows.Scan(
			&document.ID, &document.TenantID, &document.EvidenceID, &releaseID, &artifactID,
			&document.Format, &document.Author, &version, &document.StatementCount, &statusSummary,
			&document.SchemaVersion, &document.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection vex document: %w", err)
		}
		document.ReleaseID = nullableSQLString(releaseID)
		document.ArtifactID = nullableSQLString(artifactID)
		document.Version = nullableSQLString(version)
		if err := decodeJSON(statusSummary, &document.StatusSummary); err != nil {
			return fmt.Errorf("decode worker projection vex status summary: %w", err)
		}
		projection.VEXDocuments = append(projection.VEXDocuments, document)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection vex documents: %w", err)
	}
	return nil
}

func loadWorkerProjectionVEXImportReports(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id,
		       parser_version, status, statement_count, decisions_created,
		       decisions_superseded, unsupported_fields, warnings, invalid_statements,
		       mapping_failures, failure_code, failure_detail, schema_version, created_at, updated_at
		FROM vex_import_reports
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection vex import reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var report domain.VEXImportReport
		var releaseID, artifactID sql.NullString
		var warnings, invalidStatements, mappingFailures []byte
		if err := rows.Scan(
			&report.ID, &report.TenantID, &report.VEXDocumentID, &report.EvidenceID, &releaseID, &artifactID,
			&report.ParserVersion, &report.Status, &report.StatementCount, &report.DecisionsCreated,
			&report.DecisionsSuperseded, &report.UnsupportedFields, &warnings, &invalidStatements,
			&mappingFailures, &report.FailureCode, &report.FailureDetail, &report.SchemaVersion,
			&report.CreatedAt, &report.UpdatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection vex import report: %w", err)
		}
		report.ReleaseID = nullableSQLString(releaseID)
		report.ArtifactID = nullableSQLString(artifactID)
		if err := decodeJSON(warnings, &report.Warnings); err != nil {
			return fmt.Errorf("decode worker projection vex import warnings: %w", err)
		}
		if err := decodeJSON(invalidStatements, &report.InvalidStatements); err != nil {
			return fmt.Errorf("decode worker projection vex import invalid statements: %w", err)
		}
		if err := decodeJSON(mappingFailures, &report.MappingFailures); err != nil {
			return fmt.Errorf("decode worker projection vex import mapping failures: %w", err)
		}
		projection.VEXImportReports = append(projection.VEXImportReports, report)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection vex import reports: %w", err)
	}
	return nil
}

func loadWorkerProjectionBuildAttestations(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, build_id, evidence_id, payload_ref, payload_hash,
		       payload_size, payload_type, predicate_type, subject_digests,
		       builder_id, build_type, materials_count, signature_count,
		       verification_status, schema_version, created_at
		FROM build_attestations
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection build attestations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var attestation domain.BuildAttestation
		var payloadRef, builderID, buildType sql.NullString
		var subjectDigests []byte
		if err := rows.Scan(
			&attestation.ID, &attestation.TenantID, &attestation.BuildID, &attestation.EvidenceID,
			&payloadRef, &attestation.PayloadHash, &attestation.PayloadSize, &attestation.PayloadType,
			&attestation.PredicateType, &subjectDigests, &builderID, &buildType,
			&attestation.MaterialsCount, &attestation.SignatureCount, &attestation.VerificationStatus,
			&attestation.SchemaVersion, &attestation.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection build attestation: %w", err)
		}
		attestation.PayloadRef = nullableSQLString(payloadRef)
		attestation.BuilderID = nullableSQLString(builderID)
		attestation.BuildType = nullableSQLString(buildType)
		if err := decodeJSON(subjectDigests, &attestation.SubjectDigests); err != nil {
			return fmt.Errorf("decode worker projection attestation subject digests: %w", err)
		}
		projection.BuildAttestations = append(projection.BuildAttestations, attestation)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection build attestations: %w", err)
	}
	return nil
}

func loadWorkerProjectionVulnerabilityDecisions(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, finding_id, scan_id, release_id, vulnerability,
		       component, sbom_id, sbom_component_purl, sbom_component_name,
		       status, justification, impact_statement, action_statement,
		       customer_visible, internal_notes, source, evidence_id, evidence_ids,
		       supporting_refs, vex_document_id, supersedes, superseded_by,
		       approved_by, reviewed_at, review_due_at, schema_version, created_at
		FROM vulnerability_decisions
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection vulnerability decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var decision domain.VulnerabilityDecision
		var releaseID, component, sbomID, sbomComponentPURL, sbomComponentName sql.NullString
		var impactStatement, actionStatement, internalNotes, evidenceID sql.NullString
		var vexDocumentID, supersedes, supersededBy, approvedBy sql.NullString
		var reviewedAt, reviewDueAt sql.NullTime
		var supportingRefs []byte
		if err := rows.Scan(
			&decision.ID, &decision.TenantID, &decision.FindingID, &decision.ScanID, &releaseID,
			&decision.Vulnerability, &component, &sbomID, &sbomComponentPURL, &sbomComponentName,
			&decision.Status, &decision.Justification, &impactStatement, &actionStatement,
			&decision.CustomerVisible, &internalNotes, &decision.Source, &evidenceID,
			&decision.EvidenceIDs, &supportingRefs, &vexDocumentID, &supersedes, &supersededBy,
			&approvedBy, &reviewedAt, &reviewDueAt, &decision.SchemaVersion, &decision.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan worker projection vulnerability decision: %w", err)
		}
		decision.ReleaseID = nullableSQLString(releaseID)
		decision.Component = nullableSQLString(component)
		decision.SBOMID = nullableSQLString(sbomID)
		decision.SBOMComponentPURL = nullableSQLString(sbomComponentPURL)
		decision.SBOMComponentName = nullableSQLString(sbomComponentName)
		decision.ImpactStatement = nullableSQLString(impactStatement)
		decision.ActionStatement = nullableSQLString(actionStatement)
		decision.InternalNotes = nullableSQLString(internalNotes)
		decision.EvidenceID = nullableSQLString(evidenceID)
		if err := decodeJSON(supportingRefs, &decision.SupportingRefs); err != nil {
			return fmt.Errorf("decode worker projection vulnerability decision supporting refs: %w", err)
		}
		decision.VEXDocumentID = nullableSQLString(vexDocumentID)
		decision.Supersedes = nullableSQLString(supersedes)
		decision.SupersededBy = nullableSQLString(supersededBy)
		decision.ApprovedBy = nullableSQLString(approvedBy)
		decision.ReviewedAt = nullableSQLTime(reviewedAt)
		decision.ReviewDueAt = nullableSQLTime(reviewDueAt)
		projection.VulnerabilityDecisions = append(projection.VulnerabilityDecisions, decision)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection vulnerability decisions: %w", err)
	}
	return nil
}

func loadWorkerProjectionAuditChain(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, sequence, entry_type, subject_type, subject_id,
		       actor_type, actor_id, occurred_at, request_id, idempotency_key, payload_hash,
		       canonical_entry_hash, previous_entry_hash, entry_hash,
		       signature_ref, metadata, schema_version
		FROM audit_chain_entries
		WHERE tenant_id = $1
		ORDER BY sequence
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection audit chain: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var entry domain.AuditChainEntry
		var requestID, idempotencyKey, payloadHash, signatureRef sql.NullString
		var metadata []byte
		if err := rows.Scan(
			&entry.ID, &entry.TenantID, &entry.Sequence, &entry.EntryType, &entry.SubjectType,
			&entry.SubjectID, &entry.ActorType, &entry.ActorID, &entry.OccurredAt, &requestID,
			&idempotencyKey, &payloadHash, &entry.CanonicalEntryHash, &entry.PreviousEntryHash,
			&entry.EntryHash, &signatureRef, &metadata, &entry.SchemaVersion,
		); err != nil {
			return fmt.Errorf("scan worker projection audit chain entry: %w", err)
		}
		entry.RequestID = nullableSQLString(requestID)
		entry.IdempotencyKey = nullableSQLString(idempotencyKey)
		entry.PayloadHash = nullableSQLString(payloadHash)
		entry.SignatureRef = nullableSQLString(signatureRef)
		if err := decodeJSON(metadata, &entry.Metadata); err != nil {
			return fmt.Errorf("decode worker projection audit metadata: %w", err)
		}
		projection.AuditChainEntries = append(projection.AuditChainEntries, entry)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection audit chain: %w", err)
	}
	return nil
}
