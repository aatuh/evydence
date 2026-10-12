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

const importedContractDiffColumns = `id,tenant_id,base_contract_id,target_contract_id,product_id,release_id,result,document,schema_version,created_at`
const importedContractDiffRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS base_contract_id,$4::text AS target_contract_id,$5::text AS product_id,$6::text AS release_id,$7::text AS result,$8::jsonb AS document,$9::text AS schema_version,$10::timestamptz AS created_at`

// SaveState already holds the tenant projection fences. Historical records
// are insert-or-compare: a compatibility import cannot rewrite durable diffs.
func importContractDiffRow(ctx context.Context, tx pgx.Tx, v domain.ContractDiff) error {
	document, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode imported contract diff: %w", err)
	}
	args := []any{v.ID, v.TenantID, v.BaseContractID, v.TargetContractID, v.ProductID, nullableString(v.ReleaseID), v.Result, document, v.SchemaVersion, nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO contract_diffs (`+importedContractDiffColumns+`) SELECT `+importedContractDiffColumns+` FROM (`+importedContractDiffRow+`) incoming ON CONFLICT(id)DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported contract diff: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var same bool
	// Relational created_at owns precision/timezone. Only the legacy zero
	// timestamp bypasses its comparison; every other persisted field matches.
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedContractDiffRow+`) SELECT
 (to_jsonb(d)-'document'-CASE WHEN $11::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-'document'-CASE WHEN $11::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)
 AND d.document-'created_at'=i.document-'created_at' FROM contract_diffs d CROSS JOIN incoming i WHERE d.id=$1 AND d.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported contract diff: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
