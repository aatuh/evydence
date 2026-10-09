package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// The caller owns the complete read-only repeatable-read view and metadata
// budget. Policy timestamps retain microseconds for the write-time comparison.
func readCustomerPackageProfileTx(ctx context.Context, tx pgx.Tx, tenant, product, release, id string, budget *customerSnapshotBudget) (packagedomain.RedactionProfile, error) {
	var empty packagedomain.RedactionProfile
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return empty, err
	}
	if !customerSnapshotID(id, false) {
		return empty, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return empty, err
	}
	p, used, err := repositories.ReadCustomerPackageRedactionProfileSnapshot(ctx, tx, tenant, id, budget.remainingBytes)
	if err != nil {
		switch {
		case errors.Is(err, app.ErrNotFound):
			err = packageapp.ErrNotFound
		case errors.Is(err, app.ErrValidation):
			err = packageapp.ErrValidation
		case errors.Is(err, app.ErrConflict):
			err = packageapp.ErrConflict
		}
		return empty, err
	}
	if p.ID != id || p.TenantID != tenant || p.Name == "" || p.SchemaVersion == "" || len(p.AllowedTypes) == 0 {
		return empty, packageapp.ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	budget.remainingBytes -= used
	return p, nil
}
