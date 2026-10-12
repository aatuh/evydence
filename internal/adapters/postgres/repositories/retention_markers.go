package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// A flat current-ownership guard transfers no subject payload or metadata.
// The caller takes the actor-tenant fence before these share locks, which
// prevent deletion or ownership changes through the enclosing replay commit.
func (r governance) LockRetentionMarkerScope(ctx context.Context, tenant, kind, id string) error {
	if ctx == nil || r.tx == nil || !validRetentionCoordinate(tenant) || !validRetentionCoordinate(id) {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	k, normalized, err := operationsapp.NormalizeRetentionMarkerScope(kind, id)
	if err != nil || k != kind || normalized != id {
		return app.ErrValidation
	}
	var sql string
	switch kind {
	case "tenant":
		if id != tenant {
			return app.ErrNotFound
		}
		sql = `SELECT 1 FROM tenants WHERE id=$1 AND id=$2 FOR SHARE`
	case "product":
		sql = `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "project":
		sql = `SELECT 1 FROM projects WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "release":
		sql = `SELECT 1 FROM releases WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "evidence":
		sql = `SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	default:
		return app.ErrValidation
	}
	return requireRow(ctx, r.tx, sql, tenant, id)
}
