package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.VEXPointReader = (*Store)(nil)

const maxVEXReportJSONBytes = 16 << 20

func (s *Store) GetVEXDocumentPoint(ctx context.Context, tenantID, id string) (evidencequery.VEXDocumentPoint, error) {
	tx, err := s.beginVEXPointSnapshot(ctx, tenantID, id)
	if err != nil {
		return evidencequery.VEXDocumentPoint{}, err
	}
	defer rollbackVEXPointSnapshot(ctx, tx)
	return loadVEXDocumentPointInTx(ctx, tx, tenantID, strings.TrimSpace(id))
}

func (s *Store) GetVEXImportReportPoint(ctx context.Context, tenantID, vexID string) (evidencequery.VEXImportReportPoint, error) {
	tx, err := s.beginVEXPointSnapshot(ctx, tenantID, vexID)
	if err != nil {
		return evidencequery.VEXImportReportPoint{}, err
	}
	defer rollbackVEXPointSnapshot(ctx, tx)
	document, err := loadVEXDocumentPointInTx(ctx, tx, tenantID, strings.TrimSpace(vexID))
	if err != nil {
		return evidencequery.VEXImportReportPoint{}, err
	}
	var point evidencequery.VEXImportReportPoint
	point.Document = document
	report := &point.Report
	var releaseID, artifactID sql.NullString
	var warningsJSON, invalidJSON, failuresJSON []byte
	var count int
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id,
		       parser_version, status, statement_count, decisions_created,
		       decisions_superseded, unsupported_fields, warnings, invalid_statements,
		       mapping_failures, failure_code, failure_detail, schema_version, created_at,
		       updated_at, COUNT(*) OVER ()
		FROM vex_import_reports
		WHERE tenant_id = $1 AND vex_document_id = $2
		ORDER BY created_at DESC, id DESC LIMIT 1`, tenantID, strings.TrimSpace(vexID)).Scan(
		&report.ID, &report.TenantID, &report.VEXDocumentID, &report.EvidenceID, &releaseID, &artifactID,
		&report.ParserVersion, &report.Status, &report.StatementCount, &report.DecisionsCreated,
		&report.DecisionsSuperseded, &report.UnsupportedFields, &warningsJSON, &invalidJSON,
		&failuresJSON, &report.FailureCode, &report.FailureDetail, &report.SchemaVersion,
		&report.CreatedAt, &report.UpdatedAt, &count)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.VEXImportReportPoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.VEXImportReportPoint{}, fmt.Errorf("get VEX import report point: %w", err)
	}
	if count != 1 || len(warningsJSON) > maxVEXReportJSONBytes || len(invalidJSON) > maxVEXReportJSONBytes || len(failuresJSON) > maxVEXReportJSONBytes {
		return evidencequery.VEXImportReportPoint{}, evidencequery.ErrConflict
	}
	report.ReleaseID, report.ArtifactID = nullableSQLString(releaseID), nullableSQLString(artifactID)
	var invalid, failures []domain.VEXImportIssue
	if err := json.Unmarshal(warningsJSON, &report.Warnings); err != nil {
		return evidencequery.VEXImportReportPoint{}, evidencequery.ErrConflict
	}
	if err := json.Unmarshal(invalidJSON, &invalid); err != nil {
		return evidencequery.VEXImportReportPoint{}, evidencequery.ErrConflict
	}
	if err := json.Unmarshal(failuresJSON, &failures); err != nil {
		return evidencequery.VEXImportReportPoint{}, evidencequery.ErrConflict
	}
	for _, issue := range invalid {
		report.InvalidStatements = append(report.InvalidStatements, evidencedomain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
	}
	for _, issue := range failures {
		report.MappingFailures = append(report.MappingFailures, evidencedomain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
	}
	if report.UpdatedAt.Before(report.CreatedAt) && report.Status != "accepted" {
		report.UpdatedAt = report.CreatedAt
	}
	return point, nil
}

func (s *Store) beginVEXPointSnapshot(ctx context.Context, tenantID, id string) (pgx.Tx, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return nil, evidencequery.ErrValidation
	}
	if strings.TrimSpace(id) == "" {
		return nil, evidencequery.ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin VEX point snapshot: %w", err)
	}
	return tx, nil
}

func rollbackVEXPointSnapshot(ctx context.Context, tx pgx.Tx) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanupCtx)
}

func loadVEXDocumentPointInTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (evidencequery.VEXDocumentPoint, error) {
	var point evidencequery.VEXDocumentPoint
	document := &point.Document
	var releaseID, artifactID, version sql.NullString
	var summaryJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, evidence_id, release_id, artifact_id, format, author,
		       version, statement_count, status_summary, schema_version, created_at
		FROM vex_documents WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&document.ID, &document.TenantID, &document.EvidenceID, &releaseID, &artifactID,
		&document.Format, &document.Author, &version, &document.StatementCount, &summaryJSON,
		&document.SchemaVersion, &document.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.VEXDocumentPoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.VEXDocumentPoint{}, fmt.Errorf("get VEX document point: %w", err)
	}
	document.ReleaseID, document.ArtifactID, document.Version = nullableSQLString(releaseID), nullableSQLString(artifactID), nullableSQLString(version)
	source, err := loadParserReplayEvidence(ctx, tx, tenantID, document.EvidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.VEXDocumentPoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.VEXDocumentPoint{}, err
	}
	if source.Type != "vex" || source.TenantID != document.TenantID || source.ReleaseID != document.ReleaseID || !vexArtifactSubjectMatches(source.SubjectRefs, document.ArtifactID) {
		return evidencequery.VEXDocumentPoint{}, evidencequery.ErrNotFound
	}
	productID, _, resolvedReleaseID, err := resolveEvidencePointScope(ctx, tx, source)
	if err != nil {
		return evidencequery.VEXDocumentPoint{}, err
	}
	if resolvedReleaseID != document.ReleaseID {
		return evidencequery.VEXDocumentPoint{}, evidencequery.ErrNotFound
	}
	if document.ArtifactID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM artifacts WHERE tenant_id = $1 AND id = $2)`, tenantID, document.ArtifactID).Scan(&exists); err != nil {
			return evidencequery.VEXDocumentPoint{}, fmt.Errorf("check VEX artifact parent: %w", err)
		}
		if !exists {
			return evidencequery.VEXDocumentPoint{}, evidencequery.ErrNotFound
		}
	}
	if len(summaryJSON) > maxVEXReportJSONBytes || json.Unmarshal(summaryJSON, &document.StatusSummary) != nil {
		return evidencequery.VEXDocumentPoint{}, evidencequery.ErrConflict
	}
	point.ProductID = productID
	return point, nil
}

func vexArtifactSubjectMatches(refs []domain.SubjectRef, artifactID string) bool {
	seen := make(map[string]struct{})
	for _, ref := range refs {
		if ref.Type == "artifact" && ref.ID != "" {
			seen[ref.ID] = struct{}{}
		}
	}
	if artifactID == "" {
		return len(seen) == 0
	}
	_, ok := seen[artifactID]
	return ok && len(seen) == 1
}
