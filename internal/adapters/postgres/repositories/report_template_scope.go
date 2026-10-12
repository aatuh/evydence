package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
)

func (r packages) LockReportTemplateTenant(ctx context.Context, tenant string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
}
func (r packages) LockReportTemplateIdentity(ctx context.Context, tenant, id string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM report_templates WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
}
