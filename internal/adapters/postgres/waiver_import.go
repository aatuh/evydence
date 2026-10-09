package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const importedWaiverColumns = `id,tenant_id,scope_type,scope_id,control_id,policy_id,owner,risk,reason,expires_at,approved,approved_by,approved_at,supersedes,superseded_by,schema_version,created_at`
const importedWaiverRow = `SELECT $1::text AS id,$2::text AS tenant_id,$3::text AS scope_type,$4::text AS scope_id,$5::text AS control_id,$6::text AS policy_id,$7::text AS owner,$8::text AS risk,$9::text AS reason,$10::timestamptz AS expires_at,$11::boolean AS approved,$12::text AS approved_by,$13::timestamptz AS approved_at,$14::text AS supersedes,$15::text AS superseded_by,$16::text AS schema_version,$17::timestamptz AS created_at`

// importWaiverRow is for trusted relational import/sync, not API authorization.
// Initial inserts retain legacy history. Existing records are never rewritten;
// an unchanged older snapshot may omit later lifecycle metadata without undoing
// it. New transitions require the focused conditional writers, not bulk replay.
// The caller holds tenant projection fences through the enclosing transaction.
func importWaiverRow(ctx context.Context, tx pgx.Tx, v domain.Waiver) error {
	args := []any{v.ID, v.TenantID, v.ScopeType, v.ScopeID, nullableString(v.ControlID), nullableString(v.PolicyID), v.Owner, v.Risk, v.Reason, v.ExpiresAt, v.Approved, nullableString(v.ApprovedBy), nullableTime(v.ApprovedAt), nullableString(v.Supersedes), nullableString(v.SupersededBy), v.SchemaVersion, nonZeroTime(v.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO waivers (`+importedWaiverColumns+`) SELECT `+importedWaiverColumns+` FROM (`+importedWaiverRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported waiver: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	args = append(args, v.CreatedAt.IsZero())
	var sameCore, compatibleApproval, compatibleSuccessor bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedWaiverRow+`) SELECT
 (to_jsonb(w)-CASE WHEN $18::boolean THEN ARRAY['approved','approved_by','approved_at','superseded_by','created_at'] ELSE ARRAY['approved','approved_by','approved_at','superseded_by'] END)
 = (to_jsonb(i)-CASE WHEN $18::boolean THEN ARRAY['approved','approved_by','approved_at','superseded_by','created_at'] ELSE ARRAY['approved','approved_by','approved_at','superseded_by'] END),
 (NOT i.approved AND i.approved_by IS NULL AND i.approved_at IS NULL) OR
 (i.approved=w.approved AND i.approved_by IS NOT DISTINCT FROM w.approved_by AND i.approved_at IS NOT DISTINCT FROM w.approved_at),
 i.superseded_by IS NULL OR i.superseded_by IS NOT DISTINCT FROM w.superseded_by
 FROM waivers w CROSS JOIN incoming i WHERE w.id=$1 AND w.tenant_id=$2`, args...).Scan(&sameCore, &compatibleApproval, &compatibleSuccessor)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported waiver: %w", err)
	}
	if !sameCore || !compatibleApproval || !compatibleSuccessor {
		return app.ErrConflict
	}
	return nil
}
