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

const importedPolicyColumns = `id,tenant_id,name,version,description,rules,schema_version,created_at`
const importedPolicyRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS name,$4::text AS version,$5::text AS description,$6::jsonb AS rules,$7::text AS schema_version,$8::timestamptz AS created_at`
const importedPolicyEvaluationColumns = `id,tenant_id,policy_id,release_id,result,checks,input_hash,schema_version,created_at`
const importedPolicyEvaluationRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS policy_id,$4::text AS release_id,$5::text AS result,$6::jsonb AS checks,$7::text AS input_hash,$8::text AS schema_version,$9::timestamptz AS created_at`

// Trusted replay may add historical records but must never rewrite a policy or
// evaluation already committed. The enclosing import holds projection fences.
func importCustomPolicyRow(ctx context.Context, tx pgx.Tx, p domain.CustomPolicy) error {
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return fmt.Errorf("encode imported policy rules: %w", err)
	}
	args := []any{p.ID, p.TenantID, p.Name, p.Version, nullableString(p.Description), rules, p.SchemaVersion, nonZeroTime(p.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO custom_policies (`+importedPolicyColumns+`) SELECT `+importedPolicyColumns+` FROM (`+importedPolicyRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported custom policy: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, p.CreatedAt.IsZero())
	var same bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedPolicyRow+`) SELECT (to_jsonb(p)-CASE WHEN $9::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-CASE WHEN $9::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END) FROM custom_policies p CROSS JOIN incoming i WHERE p.id=$1 AND p.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported custom policy: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
func importCustomPolicyEvaluationRow(ctx context.Context, tx pgx.Tx, e domain.CustomPolicyEvaluation) error {
	checks, err := json.Marshal(e.Checks)
	if err != nil {
		return fmt.Errorf("encode imported policy checks: %w", err)
	}
	args := []any{e.ID, e.TenantID, e.PolicyID, e.ReleaseID, e.Result, checks, e.InputHash, e.SchemaVersion, nonZeroTime(e.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO custom_policy_evaluations (`+importedPolicyEvaluationColumns+`) SELECT `+importedPolicyEvaluationColumns+` FROM (`+importedPolicyEvaluationRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported policy evaluation: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, e.CreatedAt.IsZero())
	var same bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedPolicyEvaluationRow+`) SELECT (to_jsonb(e)-CASE WHEN $10::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END)=(to_jsonb(i)-CASE WHEN $10::boolean THEN ARRAY['created_at'] ELSE ARRAY[]::text[] END) FROM custom_policy_evaluations e CROSS JOIN incoming i WHERE e.id=$1 AND e.tenant_id=$2`, args...).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported policy evaluation: %w", err)
	}
	if !same {
		return app.ErrConflict
	}
	return nil
}
