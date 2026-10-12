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

const importedBuiltInEvaluationColumns = `id,tenant_id,release_id,result,policy_set,checks,created_at`
const importedBuiltInEvaluationRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS release_id,$4::text AS result,$5::text AS policy_set,$6::jsonb AS checks,$7::timestamptz AS created_at`

// Initial trusted imports retain legacy history. Existing evaluations are
// compared, never updated, under the enclosing import's projection fences.
func importPolicyEvaluationRow(ctx context.Context, tx pgx.Tx, v domain.PolicyEvaluation) error {
	checks, err := json.Marshal(v.Checks)
	if err != nil {
		return fmt.Errorf("encode imported built-in policy checks: %w", err)
	}
	args := []any{v.ID, v.TenantID, v.ReleaseID, v.Result, v.PolicySet, checks, nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO policy_evaluations (`+importedBuiltInEvaluationColumns+`) SELECT `+importedBuiltInEvaluationColumns+` FROM (`+importedBuiltInEvaluationRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported built-in policy evaluation: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var same bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedBuiltInEvaluationRow+`) SELECT (to_jsonb(e)-CASE WHEN $8::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-CASE WHEN $8::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END) FROM policy_evaluations e CROSS JOIN incoming i WHERE e.id=$1 AND e.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported built-in evaluation: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
