package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const importedExceptionColumns = `id,tenant_id,release_id,finding_id,control_id,reason,owner,expires_at,approved,approved_by,approved_at,created_at`
const importedExceptionRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS release_id,$4::text AS finding_id,$5::text AS control_id,$6::text AS reason,$7::text AS owner,$8::timestamptz AS expires_at,$9::boolean AS approved,$10::text AS approved_by,$11::timestamptz AS approved_at,$12::timestamptz AS created_at`

// Trusted import retains initial legacy history, but never rewrites an existing
// exception. Stale snapshots may omit approval metadata without undoing it;
// new approvals must use the focused conditional writer. The caller holds
// tenant projection fences through the enclosing transaction.
func importExceptionRow(ctx context.Context, tx pgx.Tx, v domain.Exception) error {
	args := []any{v.ID, v.TenantID, v.ReleaseID, nullableString(v.FindingID), nullableString(v.ControlID), v.Reason, v.Owner, v.ExpiresAt, v.Approved, nullableString(v.ApprovedBy), nullableTime(v.ApprovedAt), nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO exceptions (`+importedExceptionColumns+`) SELECT `+importedExceptionColumns+` FROM (`+importedExceptionRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported exception: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var sameCore, compatibleApproval bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedExceptionRow+`) SELECT
 (to_jsonb(e)-CASE WHEN $13::boolean THEN ARRAY['approved','approved_by','approved_at','created_at'] ELSE ARRAY['approved','approved_by','approved_at'] END)
 = (to_jsonb(i)-CASE WHEN $13::boolean THEN ARRAY['approved','approved_by','approved_at','created_at'] ELSE ARRAY['approved','approved_by','approved_at'] END),
 (NOT i.approved AND i.approved_by IS NULL AND i.approved_at IS NULL) OR
 (i.approved=e.approved AND i.approved_by IS NOT DISTINCT FROM e.approved_by AND i.approved_at IS NOT DISTINCT FROM e.approved_at)
 FROM exceptions e CROSS JOIN incoming i WHERE e.id=$1 AND e.tenant_id=$2`, args...).Scan(&sameCore, &compatibleApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported exception: %w", err)
	}
	if !sameCore || !compatibleApproval {
		return app.ErrConflict
	}
	return nil
}
