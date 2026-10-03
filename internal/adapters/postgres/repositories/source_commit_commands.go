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

func (r source) LockSourceRepositoryForWrite(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	// Projection/audit writers acquire this fence before relational locks.
	// Locking the repository also serializes a SHA whose row does not exist yet.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return integrationapp.SourceRepositoryIdentity{}, err
	}
	var v integrationapp.SourceRepositoryIdentity
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(COALESCE(project_id,''),1025) FROM source_repositories WHERE tenant_id=$1 AND id=$2 FOR NO KEY UPDATE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProjectID)
	if err := sourceIdentityError(err, v.ID, v.TenantID, v.ProjectID); err != nil {
		return integrationapp.SourceRepositoryIdentity{}, err
	}
	if v.ProjectID != "" {
		p, err := r.LockRepositoryProject(ctx, tenant, v.ProjectID)
		if err != nil {
			return integrationapp.SourceRepositoryIdentity{}, err
		}
		v.ProductID = p.ProductID
	}
	return v, nil
}
func (r source) SourceCommitBySHA(ctx context.Context, tenant, repository, sha string) (integrationdomain.SourceCommit, bool, error) {
	var v integrationdomain.SourceCommit
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(repository_id,1025),left(sha,41),left(COALESCE(author,''),65537),left(COALESCE(message_hash,''),72),committed_at,left(schema_version,1025),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(repository_id)>1024 OR octet_length(sha)>40 OR COALESCE(octet_length(author),0)>65536 OR COALESCE(octet_length(message_hash),0)>71 OR octet_length(schema_version)>1024
 FROM source_commits WHERE tenant_id=$1 AND repository_id=$2 AND sha=$3 FOR SHARE`, tenant, repository, sha).Scan(&v.ID, &v.TenantID, &v.RepositoryID, &v.SHA, &v.Author, &v.MessageHash, &v.CommittedAt, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return integrationdomain.SourceCommit{}, false, nil
	}
	if err != nil {
		return integrationdomain.SourceCommit{}, false, fmt.Errorf("read source commit: %w", err)
	}
	if large {
		return integrationdomain.SourceCommit{}, false, app.ErrConflict
	}
	v.CommittedAt, v.CreatedAt = v.CommittedAt.UTC(), v.CreatedAt.UTC()
	return v, true, nil
}
