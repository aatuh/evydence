package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
)

// loadWorkerProjectionParserNormalizations intentionally selects only the
// append-only records created by explicit parser replay. Ordinary evidence is
// owned by API command paths and is not widened into the worker projection.
func loadWorkerProjectionParserNormalizations(ctx context.Context, tx pgx.Tx, tenantID string, projection *app.WorkerProjection) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
		       type, subtype, title, source_system, source_identity, collector_id,
		       uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
		       payload_hash, payload_media_type, payload_size, canonical_hash,
		       canonicalization, subject_refs, related_evidence_refs, supersedes,
		       superseded_by, trust_level, verification_status, signature_refs,
		       chain_entry_id, tags, metadata, warnings, limitations, created_at
		FROM evidence_items
		WHERE tenant_id = $1 AND type = 'parser_normalization'
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return fmt.Errorf("load worker projection parser normalizations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanEvidencePageRow(rows)
		if err != nil {
			return fmt.Errorf("scan worker projection parser normalization: %w", err)
		}
		projection.ParserNormalizations = append(projection.ParserNormalizations, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate worker projection parser normalizations: %w", err)
	}
	return nil
}
