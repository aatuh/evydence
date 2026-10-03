package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// ReadEvidenceBundleCoordinates selects bounded reference fields only. It is
// shared by snapshot readers and the commit-time row-locking guard.
func ReadEvidenceBundleCoordinates(ctx context.Context, tx pgx.Tx, tenantID, id string, lock bool) (application.ResourceReferences, error) {
	statement := `SELECT left(coalesce(product_id,''),1025),left(coalesce(project_id,''),1025),left(coalesce(release_id,''),1025),left(coalesce(build_id,''),1025),left(coalesce(deployment_id,''),1025),
	 coalesce(octet_length(product_id)>1024,false) OR coalesce(octet_length(project_id)>1024,false) OR coalesce(octet_length(release_id)>1024,false) OR coalesce(octet_length(build_id)>1024,false) OR coalesce(octet_length(deployment_id)>1024,false)
	 FROM evidence_items WHERE tenant_id=$1 AND id=$2`
	if lock {
		statement += ` FOR SHARE`
	}
	var refs application.ResourceReferences
	var oversized bool
	err := tx.QueryRow(ctx, statement, tenantID, id).Scan(&refs.ProductID, &refs.ProjectID, &refs.ReleaseID, &refs.BuildID, &refs.DeploymentID, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return refs, app.ErrNotFound
	}
	if err != nil {
		return refs, fmt.Errorf("read bundle evidence coordinates: %w", err)
	}
	if oversized || strings.TrimSpace(id) == "" || len(id) > 1024 {
		return application.ResourceReferences{}, app.ErrConflict
	}
	return refs, nil
}

func ResolveEvidenceBundleCoordinates(ctx context.Context, tx pgx.Tx, tenantID string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	product, project, release, err := ResolveEvidenceScope(ctx, tx, domain.EvidenceItem{TenantID: tenantID, ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	refs.ProductID, refs.ProjectID, refs.ReleaseID = product, project, release
	return refs, nil
}

// LockEvidenceBundleEvidence locks the evidence row and every resolved parent
// before returning authorization coordinates. No raw evidence is loaded.
func (r evidence) LockEvidenceBundleEvidence(ctx context.Context, tenantID, id string) (application.ResourceReferences, error) {
	raw, err := ReadEvidenceBundleCoordinates(ctx, r.tx, tenantID, id, true)
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return r.lockEvidenceBundleCoordinates(ctx, tenantID, raw)
}

// The caller has already share-locked the selected evidence coordinates.
func (r evidence) lockEvidenceBundleCoordinates(ctx context.Context, tenantID string, raw application.ResourceReferences) (application.ResourceReferences, error) {
	refs, err := ResolveEvidenceBundleCoordinates(ctx, r.tx, tenantID, raw)
	if err != nil {
		if errors.Is(err, evidencequery.ErrNotFound) {
			return application.ResourceReferences{}, app.ErrConflict
		}
		return application.ResourceReferences{}, err
	}
	// Lock the tenant and product as well; ValidateEvidenceScope locks other
	// parent rows but its optional-product existence check is not a row lock.
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenantID); err != nil {
		return application.ResourceReferences{}, err
	}
	if refs.ProductID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenantID, refs.ProductID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	if err := r.ValidateEvidenceScope(ctx, tenantID, refs.ProductID, refs.ProjectID, refs.ReleaseID, refs.BuildID, refs.DeploymentID); err != nil {
		return application.ResourceReferences{}, err
	}
	return refs, nil
}
