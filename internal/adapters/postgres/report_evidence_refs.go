package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// verifyScopedReportEvidence checks a complete set of report references in
// the caller's committed read view. A false result means at least one ID is
// missing or outside the tenant, product, project, or release scope.
func verifyScopedReportEvidence(ctx context.Context, tx pgx.Tx, tenantID, productID, releaseID string, ids []string) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	var verified int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM evidence_items AS e
		LEFT JOIN projects AS j ON j.id=e.project_id AND j.tenant_id=e.tenant_id
		LEFT JOIN releases AS r ON r.id=e.release_id AND r.tenant_id=e.tenant_id
		WHERE e.tenant_id=$1 AND e.id=ANY($4::text[])
		  AND (e.product_id IS NULL OR e.product_id=$2)
		  AND (e.project_id IS NULL OR j.product_id=$2)
		  AND (e.release_id IS NULL OR (r.id=$3 AND r.product_id=$2))`,
		tenantID, productID, releaseID, ids).Scan(&verified); err != nil {
		return false, fmt.Errorf("verify report evidence references: %w", err)
	}
	return verified == len(ids), nil
}
