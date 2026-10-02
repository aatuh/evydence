package repositories

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidenceCreationScopeReader = evidence{}

// ResolveEvidenceCreationScope reads only parent identifiers and share-locks
// their coherent ownership through commit. The projection fence must precede
// row locks, following the worker/audit lock order.
func (r evidence) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) {
		return application.ResourceReferences{}, app.ErrValidation
	}
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return application.ResourceReferences{}, err
	}
	for _, id := range []string{tenant, refs.ProductID, refs.ProjectID, refs.ReleaseID, refs.BuildID, refs.DeploymentID} {
		if strings.TrimSpace(id) != id {
			return application.ResourceReferences{}, app.ErrValidation
		}
		if id != "" {
			if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
				return application.ResourceReferences{}, err
			}
		}
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return application.ResourceReferences{}, err
	}
	p, j, l, err := ResolveEvidenceScope(ctx, r.tx, domain.EvidenceItem{TenantID: tenant, ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
	if err != nil {
		if errors.Is(err, evidencequery.ErrNotFound) {
			err = app.ErrNotFound
		}
		return application.ResourceReferences{}, err
	}
	refs.ProductID, refs.ProjectID, refs.ReleaseID = p, j, l
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return application.ResourceReferences{}, err
	}
	if p != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, p); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	// Validate using resolved coordinates, not optional input alone: a parent
	// changed between resolution and locking cannot authorize its old owner.
	if err := r.ValidateEvidenceScope(ctx, tenant, p, j, l, refs.BuildID, refs.DeploymentID); err != nil {
		return application.ResourceReferences{}, err
	}
	return refs, nil
}
