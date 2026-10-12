package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
)

func (r deployments) LockDeploymentTenant(ctx context.Context, tenant string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
}
