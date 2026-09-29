package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// loadWorkerVEXJobState reads the document's source, reports, release scans,
// related decisions, the matching acceptance audit entry, and audit tail under
// one stable snapshot. It never reconstructs unrelated tenant resources or
// another tenant's state.
func (s *Store) loadWorkerVEXJobState(ctx context.Context, job ClaimedJob) (app.PersistedState, error) {
	tx, err := s.beginVEXPointSnapshot(ctx, job.TenantID, job.SubjectID)
	if err != nil {
		return app.PersistedState{}, err
	}
	defer rollbackVEXPointSnapshot(ctx, tx)
	point, err := loadVEXDocumentPointInTx(ctx, tx, job.TenantID, job.SubjectID)
	if err != nil {
		return app.PersistedState{}, err
	}
	source, err := loadParserReplayEvidence(ctx, tx, job.TenantID, point.Document.EvidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.PersistedState{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return app.PersistedState{}, err
	}
	state := app.PersistedState{
		Evidence: map[string]domain.EvidenceItem{source.ID: source},
		VEXDocuments: map[string]domain.VEXDocument{
			job.SubjectID: workerVEXDocument(point.Document),
		},
		VEXImportReports: map[string]domain.VEXImportReport{},
		Scans:            map[string]domain.VulnerabilityScan{},
		Decisions:        map[string]domain.VulnerabilityDecision{},
		Chain:            map[string][]domain.AuditChainEntry{},
	}
	if err := loadWorkerVEXReports(ctx, tx, job.TenantID, point.Document, &state); err != nil {
		return app.PersistedState{}, err
	}
	if err := loadWorkerVEXReleaseScans(ctx, tx, job.TenantID, point.Document.ReleaseID, &state); err != nil {
		return app.PersistedState{}, err
	}
	if err := loadWorkerVEXFindingDecisions(ctx, tx, job.TenantID, &state); err != nil {
		return app.PersistedState{}, err
	}
	actorType, _ := job.Payload["actor_type"].(string)
	actorID, _ := job.Payload["actor_id"].(string)
	payloadHash, _ := job.Payload["payload_hash"].(string)
	entries, err := loadVEXAcceptedAuditPoints(ctx, tx, job.TenantID, job.SubjectID, actorType, actorID, payloadHash)
	if err != nil {
		return app.PersistedState{}, err
	}
	state.Chain[job.TenantID] = entries
	return state, nil
}

func workerVEXDocument(value evidencedomain.VEXDocument) domain.VEXDocument {
	out := domain.VEXDocument{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format,
		Author: value.Author, Version: value.Version, StatementCount: value.StatementCount,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
	if value.StatusSummary != nil {
		out.StatusSummary = make(map[string]int, len(value.StatusSummary))
		for status, count := range value.StatusSummary {
			out.StatusSummary[status] = count
		}
	}
	return out
}

func loadWorkerVEXReports(ctx context.Context, tx pgx.Tx, tenantID string, vex evidencedomain.VEXDocument, state *app.PersistedState) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id,
		       parser_version, status, statement_count, decisions_created,
		       decisions_superseded, unsupported_fields, warnings, invalid_statements,
		       mapping_failures, failure_code, failure_detail, schema_version,
		       created_at, updated_at
		FROM vex_import_reports
		WHERE tenant_id = $1 AND vex_document_id = $2
		ORDER BY id`, tenantID, vex.ID)
	if err != nil {
		return fmt.Errorf("load worker VEX reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var report domain.VEXImportReport
		var releaseID, artifactID sql.NullString
		var warnings, invalid, failures []byte
		if err := rows.Scan(
			&report.ID, &report.TenantID, &report.VEXDocumentID, &report.EvidenceID,
			&releaseID, &artifactID, &report.ParserVersion, &report.Status,
			&report.StatementCount, &report.DecisionsCreated, &report.DecisionsSuperseded,
			&report.UnsupportedFields, &warnings, &invalid, &failures,
			&report.FailureCode, &report.FailureDetail, &report.SchemaVersion,
			&report.CreatedAt, &report.UpdatedAt); err != nil {
			return fmt.Errorf("scan worker VEX report: %w", err)
		}
		report.ReleaseID, report.ArtifactID = nullableSQLString(releaseID), nullableSQLString(artifactID)
		if report.EvidenceID != vex.EvidenceID || report.ReleaseID != vex.ReleaseID || report.ArtifactID != vex.ArtifactID ||
			len(warnings) > maxVEXReportJSONBytes || len(invalid) > maxVEXReportJSONBytes || len(failures) > maxVEXReportJSONBytes {
			return app.ErrConflict
		}
		if err := decodeJSON(warnings, &report.Warnings); err != nil {
			return app.ErrConflict
		}
		if err := decodeJSON(invalid, &report.InvalidStatements); err != nil {
			return app.ErrConflict
		}
		if err := decodeJSON(failures, &report.MappingFailures); err != nil {
			return app.ErrConflict
		}
		state.VEXImportReports[report.ID] = report
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker VEX reports: %w", err)
	}
	return nil
}

func loadWorkerVEXReleaseScans(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, state *app.PersistedState) error {
	if releaseID == "" {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id FROM vulnerability_scans WHERE tenant_id = $1 AND release_id = $2 ORDER BY id`, tenantID, releaseID)
	if err != nil {
		return fmt.Errorf("list worker VEX release scans: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan worker VEX release scan ID: %w", err)
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fmt.Errorf("iterate worker VEX release scan IDs: %w", err)
	}
	for _, id := range ids {
		point, err := loadVulnerabilityScanPointInTx(ctx, tx, tenantID, id)
		if err != nil {
			return fmt.Errorf("load worker VEX release scan: %w", err)
		}
		if point.Scan.ReleaseID != releaseID {
			return app.ErrConflict
		}
		state.Scans[id] = parserVulnerabilityScan(point.Scan)
	}
	return nil
}

func loadWorkerVEXFindingDecisions(ctx context.Context, tx pgx.Tx, tenantID string, state *app.PersistedState) error {
	findings := make(map[string]struct{})
	for _, scan := range state.Scans {
		for _, finding := range scan.Findings {
			if finding.ID != "" {
				findings[finding.ID] = struct{}{}
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	ids := make([]string, 0, len(findings))
	for id := range findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, finding_id, scan_id, release_id, vulnerability,
		       component, sbom_id, sbom_component_purl, sbom_component_name,
		       status, justification, impact_statement, action_statement,
		       customer_visible, internal_notes, source, evidence_id, evidence_ids,
		       supporting_refs, vex_document_id, supersedes, superseded_by,
		       approved_by, reviewed_at, review_due_at, schema_version, created_at
		FROM vulnerability_decisions
		WHERE tenant_id = $1 AND finding_id = ANY($2::text[])
		ORDER BY id`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("load worker VEX finding decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var decision domain.VulnerabilityDecision
		var releaseID, component, sbomID, sbomPURL, sbomName sql.NullString
		var impact, action, notes, evidenceID, vexID, supersedes, supersededBy, approvedBy sql.NullString
		var reviewedAt, reviewDueAt sql.NullTime
		var supportingRefs []byte
		if err := rows.Scan(
			&decision.ID, &decision.TenantID, &decision.FindingID, &decision.ScanID,
			&releaseID, &decision.Vulnerability, &component, &sbomID, &sbomPURL,
			&sbomName, &decision.Status, &decision.Justification, &impact, &action,
			&decision.CustomerVisible, &notes, &decision.Source, &evidenceID,
			&decision.EvidenceIDs, &supportingRefs, &vexID, &supersedes,
			&supersededBy, &approvedBy, &reviewedAt, &reviewDueAt,
			&decision.SchemaVersion, &decision.CreatedAt); err != nil {
			return fmt.Errorf("scan worker VEX finding decision: %w", err)
		}
		decision.ReleaseID = nullableSQLString(releaseID)
		decision.Component = nullableSQLString(component)
		decision.SBOMID = nullableSQLString(sbomID)
		decision.SBOMComponentPURL = nullableSQLString(sbomPURL)
		decision.SBOMComponentName = nullableSQLString(sbomName)
		decision.ImpactStatement = nullableSQLString(impact)
		decision.ActionStatement = nullableSQLString(action)
		decision.InternalNotes = nullableSQLString(notes)
		decision.EvidenceID = nullableSQLString(evidenceID)
		decision.VEXDocumentID = nullableSQLString(vexID)
		decision.Supersedes = nullableSQLString(supersedes)
		decision.SupersededBy = nullableSQLString(supersededBy)
		decision.ApprovedBy = nullableSQLString(approvedBy)
		decision.ReviewedAt = nullableSQLTime(reviewedAt)
		decision.ReviewDueAt = nullableSQLTime(reviewDueAt)
		if err := decodeJSON(supportingRefs, &decision.SupportingRefs); err != nil {
			return app.ErrConflict
		}
		state.Decisions[decision.ID] = decision
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker VEX finding decisions: %w", err)
	}
	return nil
}
