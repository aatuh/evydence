package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const importedSBOMDiffColumns = `id,tenant_id,base_sbom_id,target_sbom_id,release_id,document,schema_version,created_at`
const importedSBOMDiffRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS base_sbom_id,$4::text AS target_sbom_id,$5::text AS release_id,$6::jsonb AS document,$7::text AS schema_version,$8::timestamptz AS created_at`
const importedDependencyColumns = `id,tenant_id,sbom_diff_id,change_type,component,schema_version,created_at`
const importedDependencyRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS sbom_diff_id,$4::text AS change_type,$5::jsonb AS component,$6::text AS schema_version,$7::timestamptz AS created_at`

// These trusted import helpers run under SaveState's tenant projection fences.
// Existing diff and dependency records are compared, never updated.
func importSBOMDiffRow(ctx context.Context, tx pgx.Tx, v domain.SBOMDiff) error {
	document, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode imported SBOM diff: %w", err)
	}
	args := []any{v.ID, v.TenantID, v.BaseSBOMID, v.TargetSBOMID, nullableString(v.ReleaseID), document, v.SchemaVersion, nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO sbom_diffs (`+importedSBOMDiffColumns+`) SELECT `+importedSBOMDiffColumns+` FROM (`+importedSBOMDiffRow+`) incoming ON CONFLICT(id)DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported SBOM diff: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var same bool
	// Relational created_at is authoritative; embedded legacy timestamps can
	// differ in precision or timezone after a round trip through PostgreSQL.
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedSBOMDiffRow+`) SELECT
 (to_jsonb(d)-'document'-CASE WHEN $9::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-'document'-CASE WHEN $9::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)
 AND d.document-'created_at'=i.document-'created_at' FROM sbom_diffs d CROSS JOIN incoming i WHERE d.id=$1 AND d.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported SBOM diff: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
func importDependencyChangeRow(ctx context.Context, tx pgx.Tx, v domain.DependencyChange) error {
	component, err := json.Marshal(v.Component)
	if err != nil {
		return fmt.Errorf("encode imported dependency component: %w", err)
	}
	args := []any{v.ID, v.TenantID, v.SBOMDiffID, v.ChangeType, component, v.SchemaVersion, nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO dependency_changes (`+importedDependencyColumns+`) SELECT `+importedDependencyColumns+` FROM (`+importedDependencyRow+`) incoming ON CONFLICT(id)DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported dependency change: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var same bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedDependencyRow+`) SELECT (to_jsonb(d)-CASE WHEN $8::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-CASE WHEN $8::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END) FROM dependency_changes d CROSS JOIN incoming i WHERE d.id=$1 AND d.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported dependency change: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
