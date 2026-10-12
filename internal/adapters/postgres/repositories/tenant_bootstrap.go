package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
)

// LockAndCheckTenantBootstrap stabilizes the installation-wide absence of
// tenants, including the empty-table case. Ordinary tenant inserts also take
// a conflicting table lock, so the guard does not rely on other writers using
// the bootstrap helper. No tenant names or credentials are selected.
func (r identity) LockAndCheckTenantBootstrap(ctx context.Context) (bool, error) {
	if ctx == nil || r.tx == nil {
		return false, app.ErrValidation
	}
	if _, err := r.tx.Exec(ctx, `LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, writeError("lock tenant bootstrap", err)
	}
	var exists bool
	if err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants)`).Scan(&exists); err != nil {
		return false, writeError("check tenant bootstrap", err)
	}
	return exists, nil
}
