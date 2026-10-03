package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

var _ operationsapp.IncidentReader = risk{}

// ReadIncidentSubject is a tenant-and-ID point lookup, not a document or
// inventory reader. The projection fence precedes row locks, matching worker
// and audit lock order; coherent parents stay locked through command commit.
func (r risk) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (operationsapp.IncidentSubject, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return operationsapp.IncidentSubject{}, err
	}
	if strings.TrimSpace(tenant) != tenant || strings.TrimSpace(id) != id {
		return operationsapp.IncidentSubject{}, app.ErrValidation
	}
	refs := application.ResourceReferences{}
	switch kind {
	case "product":
		refs.ProductID = id
	case "release":
		refs.ReleaseID = id
	case "incident", "evidence":
		if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
			return operationsapp.IncidentSubject{}, err
		}
		var err error
		var oversized bool
		if kind == "incident" {
			err = r.tx.QueryRow(ctx, `SELECT left(product_id,1025),left(COALESCE(release_id,''),1025),octet_length(product_id)>1024 OR octet_length(COALESCE(release_id,''))>1024 FROM incidents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&refs.ProductID, &refs.ReleaseID, &oversized)
		} else {
			err = r.tx.QueryRow(ctx, `SELECT left(COALESCE(product_id,''),1025),left(COALESCE(project_id,''),1025),left(COALESCE(release_id,''),1025),left(COALESCE(build_id,''),1025),left(COALESCE(deployment_id,''),1025),octet_length(COALESCE(product_id,''))>1024 OR octet_length(COALESCE(project_id,''))>1024 OR octet_length(COALESCE(release_id,''))>1024 OR octet_length(COALESCE(build_id,''))>1024 OR octet_length(COALESCE(deployment_id,''))>1024 FROM evidence_items WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&refs.ProductID, &refs.ProjectID, &refs.ReleaseID, &refs.BuildID, &refs.DeploymentID, &oversized)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return operationsapp.IncidentSubject{}, app.ErrNotFound
		}
		if err != nil {
			return operationsapp.IncidentSubject{}, fmt.Errorf("read incident reference coordinates: %w", err)
		}
		if oversized {
			return operationsapp.IncidentSubject{}, app.ErrValidation
		}
		if kind == "incident" && refs.ProductID == "" {
			return operationsapp.IncidentSubject{}, app.ErrNotFound
		}
	default:
		return operationsapp.IncidentSubject{}, app.ErrValidation
	}
	resolved, err := evidence(r).ResolveEvidenceCreationScope(ctx, tenant, refs)
	if err != nil {
		return operationsapp.IncidentSubject{}, err
	}
	return operationsapp.IncidentSubject{ID: id, TenantID: tenant, Type: kind, Resources: resolved}, nil
}
