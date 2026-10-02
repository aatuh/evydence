package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func (r deployments) LockDeploymentEnvironment(ctx context.Context, tenant, id string) (operationsapp.DeploymentEnvironmentIdentity, error) {
	var v operationsapp.DeploymentEnvironmentIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(product_id,1025) FROM deployment_environments WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID)
	if err := deploymentIdentityError(err, v.ID, v.TenantID, v.ProductID); err != nil {
		return operationsapp.DeploymentEnvironmentIdentity{}, err
	}
	return v, nil
}
func (r deployments) LockDeploymentRelease(ctx context.Context, tenant, id string) (operationsapp.DeploymentReleaseIdentity, error) {
	var v operationsapp.DeploymentReleaseIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(product_id,1025) FROM releases WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID)
	if err := deploymentIdentityError(err, v.ID, v.TenantID, v.ProductID); err != nil {
		return operationsapp.DeploymentReleaseIdentity{}, err
	}
	return v, nil
}
func (r deployments) LockDeploymentRollback(ctx context.Context, tenant, id string) (operationsapp.DeploymentRollbackIdentity, error) {
	var v operationsapp.DeploymentRollbackIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(environment_id,1025) FROM deployment_events WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.EnvironmentID)
	if err := deploymentIdentityError(err, v.ID, v.TenantID, v.EnvironmentID); err != nil {
		return operationsapp.DeploymentRollbackIdentity{}, err
	}
	return v, nil
}
func deploymentIdentityError(err error, ids ...string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read deployment identity: %w", err)
	}
	for _, id := range ids {
		if len(id) > 1024 {
			return app.ErrConflict
		}
	}
	return nil
}
func (r deployments) CheckDeploymentArtifacts(ctx context.Context, tenant string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) > operationsapp.MaxDeploymentArtifacts {
		return app.ErrValidation
	}
	// Lock only referenced identities, in deterministic order; never select
	// names, payloads, digests, or unrelated tenant artifact collections.
	rows, err := r.tx.Query(ctx, `SELECT left(id,1025),left(tenant_id,1025) FROM artifacts WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id FOR SHARE`, tenant, ids)
	if err != nil {
		return fmt.Errorf("read deployment artifact identities: %w", err)
	}
	defer rows.Close()
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	for rows.Next() {
		var id, owner string
		if err := rows.Scan(&id, &owner); err != nil {
			return err
		}
		if err := deploymentIdentityError(nil, id, owner); err != nil {
			return err
		}
		if owner != tenant || !want[id] {
			return app.ErrNotFound
		}
		delete(want, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(want) != 0 {
		return app.ErrNotFound
	}
	return nil
}
