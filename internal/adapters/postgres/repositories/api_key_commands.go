package repositories

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

var _ identityapp.APIKeyWriteReader = identity{}

// Match worker/audit lock ordering and keep the current tenant stable. No
// key hashes, names, grants or global credential inventories are loaded.
func (r identity) LockAPIKeyCreation(ctx context.Context, tenant string) error {
	if ctx == nil || r.tx == nil || tenant == "" || len(tenant) > 1024 || !utf8.ValidString(tenant) || strings.ContainsRune(tenant, 0) || strings.TrimSpace(tenant) != tenant {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant)
}
