package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func (r source) SourceCommitIdentityByID(ctx context.Context, tenant, repository, id string) (integrationapp.SourceCommitIdentity, error) {
	var v integrationapp.SourceCommitIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(repository_id,1025) FROM source_commits WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 FOR KEY SHARE`, tenant, repository, id).Scan(&v.ID, &v.TenantID, &v.RepositoryID)
	if err := sourceIdentityError(err, v.ID, v.TenantID, v.RepositoryID); err != nil {
		return integrationapp.SourceCommitIdentity{}, err
	}
	return v, nil
}
func (r source) SourceBranchByName(ctx context.Context, tenant, repository, name string) (integrationdomain.SourceBranch, bool, error) {
	var v integrationdomain.SourceBranch
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(repository_id,1025),left(name,2305),left(COALESCE(head_commit_id,''),1025),protected,left(COALESCE(protection_hash,''),65537),left(schema_version,1025),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(repository_id)>1024 OR octet_length(name)>2304 OR COALESCE(octet_length(head_commit_id),0)>1024 OR COALESCE(octet_length(protection_hash),0)>65536 OR octet_length(schema_version)>1024
 FROM source_branches WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 FOR UPDATE`, tenant, repository, name).Scan(&v.ID, &v.TenantID, &v.RepositoryID, &v.Name, &v.HeadCommitID, &v.Protected, &v.ProtectionHash, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return integrationdomain.SourceBranch{}, false, nil
	}
	if err != nil {
		return integrationdomain.SourceBranch{}, false, fmt.Errorf("read source branch: %w", err)
	}
	if large {
		return integrationdomain.SourceBranch{}, false, app.ErrConflict
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, true, nil
}
