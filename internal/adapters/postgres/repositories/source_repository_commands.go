package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func (r source) LockRepositoryCreation(ctx context.Context, tenant string) error {
	// Take the projection fence before relational locks: audit appenders and
	// worker publication use this order. The tenant lock serializes reuse even
	// when no repository with the requested name exists yet.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	var one int
	err := r.tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	return err
}
func (r source) LockRepositoryProject(ctx context.Context, tenant, id string) (integrationapp.SourceProjectIdentity, error) {
	var p integrationapp.SourceProjectIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(p.id,1025),left(p.tenant_id,1025),left(p.product_id,1025) FROM projects p JOIN products product ON product.id=p.product_id AND product.tenant_id=p.tenant_id WHERE p.tenant_id=$1 AND p.id=$2 FOR SHARE OF p,product`, tenant, id).Scan(&p.ID, &p.TenantID, &p.ProductID)
	if err := sourceIdentityError(err, p.ID, p.TenantID, p.ProductID); err != nil {
		return integrationapp.SourceProjectIdentity{}, err
	}
	return p, nil
}
func (r source) RepositoryIdentityByName(ctx context.Context, tenant, provider, name string) (integrationapp.SourceRepositoryIdentity, bool, error) {
	var v integrationapp.SourceRepositoryIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(r.id,1025),left(r.tenant_id,1025),left(COALESCE(r.project_id,''),1025),left(COALESCE(product.id,''),1025) FROM source_repositories r LEFT JOIN projects p ON p.id=r.project_id AND p.tenant_id=r.tenant_id LEFT JOIN products product ON product.id=p.product_id AND product.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.provider=$2 AND r.full_name=$3 FOR SHARE OF r`, tenant, provider, name).Scan(&v.ID, &v.TenantID, &v.ProjectID, &v.ProductID)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, false, nil
	}
	if err := sourceIdentityError(err, v.ID, v.TenantID, v.ProjectID, v.ProductID); err != nil {
		return integrationapp.SourceRepositoryIdentity{}, false, err
	}
	if v.ProjectID != "" && v.ProductID == "" {
		return integrationapp.SourceRepositoryIdentity{}, false, app.ErrNotFound
	}
	if v.ProjectID != "" {
		// FOR SHARE OF r holds the repository's project link, but the outer
		// joins above do not lock its parents. Hold those minimal identities
		// too: reuse may resolve a different project than the submitted one.
		project, err := r.LockRepositoryProject(ctx, tenant, v.ProjectID)
		if err != nil {
			return integrationapp.SourceRepositoryIdentity{}, false, err
		}
		if project.ProductID != v.ProductID {
			return integrationapp.SourceRepositoryIdentity{}, false, app.ErrNotFound
		}
	}
	return v, true, nil
}
func sourceIdentityError(err error, ids ...string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read source identity: %w", err)
	}
	for _, id := range ids {
		if len(id) > 1024 {
			return app.ErrConflict
		}
	}
	return nil
}
func (r source) ReadSourceRepository(ctx context.Context, tenant, id string) (integrationdomain.SourceRepository, error) {
	var v integrationdomain.SourceRepository
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(COALESCE(project_id,''),1025),left(provider,65537),left(full_name,65537),left(COALESCE(clone_url,''),65537),left(COALESCE(default_branch,''),65537),left(schema_version,1025),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR COALESCE(octet_length(project_id),0)>1024 OR octet_length(provider)>65536 OR octet_length(full_name)>65536 OR COALESCE(octet_length(clone_url),0)>65536 OR COALESCE(octet_length(default_branch),0)>65536 OR octet_length(schema_version)>1024
 FROM source_repositories WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProjectID, &v.Provider, &v.FullName, &v.CloneURL, &v.DefaultBranch, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return integrationdomain.SourceRepository{}, app.ErrNotFound
	}
	if err != nil {
		return integrationdomain.SourceRepository{}, fmt.Errorf("read source repository: %w", err)
	}
	if large {
		return integrationdomain.SourceRepository{}, app.ErrConflict
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, nil
}
