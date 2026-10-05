package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.ControlCreationReader = controls{}
var _ riskapp.ControlTemplateReader = controls{}

// LockControlTemplateTenant reads only current existence. The shared writer
// fence precedes the tenant lock, including standalone installation/guards,
// and both locks join the enclosing durable replay transaction.
func (r controls) LockControlTemplateTenant(ctx context.Context, tenant string) error {
	return r.lockControlTenant(ctx, tenant)
}

func (r controls) LockControlCreationTenant(ctx context.Context, tenant string) error {
	return r.lockControlTenant(ctx, tenant)
}

func (r controls) lockControlTenant(ctx context.Context, tenant string) error {
	if ctx == nil || r.tx == nil || !validRetentionCoordinate(tenant) {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
}

func (r controls) FrameworkVersionExists(ctx context.Context, tenant, slug, version string) (bool, error) {
	tenant, slug, version = strings.TrimSpace(tenant), strings.TrimSpace(slug), strings.TrimSpace(version)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, slug); err != nil {
		return false, err
	}
	if err := validBuildIdentityRead(ctx, r.tx, tenant, version); err != nil {
		return false, err
	}
	if len(slug)+len(version) > 1024 {
		return false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR KEY SHARE`, tenant); err != nil {
		return false, err
	}
	var exists bool
	if err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control_frameworks WHERE tenant_id=$1 AND slug=$2 AND version=$3)`, tenant, slug, version).Scan(&exists); err != nil {
		return false, fmt.Errorf("read framework version existence: %w", err)
	}
	return exists, nil
}

func (r controls) ControlFrameworkExists(ctx context.Context, tenant, id string) (bool, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return false, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	var exists bool
	// Lock the tenant-owned parent without transferring its potentially large
	// name/description. Foreign IDs and missing IDs have the same result.
	err := r.tx.QueryRow(ctx, `SELECT true FROM control_frameworks WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read control framework existence: %w", err)
	}
	return exists, nil
}

func (r controls) SecurityControlCodeExists(ctx context.Context, tenant, framework, code string) (bool, error) {
	tenant, framework, code = strings.TrimSpace(tenant), strings.TrimSpace(framework), strings.TrimSpace(code)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, framework); err != nil {
		return false, err
	}
	if err := validBuildIdentityRead(ctx, r.tx, tenant, code); err != nil {
		return false, err
	}
	if len(tenant)+len(framework)+len(code) > 2048 {
		return false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	var exists bool
	if err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_controls c JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.framework_id=$2 AND c.code=$3)`, tenant, framework, code).Scan(&exists); err != nil {
		return false, fmt.Errorf("read security control code existence: %w", err)
	}
	return exists, nil
}
