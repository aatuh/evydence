package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// ResolveEvidenceScope validates all stored coordinates and their tenant-owned
// parents in the caller's transaction, without selecting evidence payloads.
func ResolveEvidenceScope(ctx context.Context, tx pgx.Tx, item domain.EvidenceItem) (string, string, string, error) {
	var tenant, product, projectProduct, releaseProduct sql.NullString
	var buildProject, buildRelease, buildProduct sql.NullString
	var deploymentRelease, deploymentProduct sql.NullString
	var oversized bool
	err := tx.QueryRow(ctx, `
		SELECT left(t.id,1025), left(p.id,1025), left(j.product_id,1025), left(r.product_id,1025),
		       left(b.project_id,1025), left(b.release_id,1025), left(b.product_id,1025),
		       left(d.release_id,1025), left(d.product_id,1025),
		       coalesce(octet_length(t.id)>1024,false) OR coalesce(octet_length(p.id)>1024,false) OR
		       coalesce(octet_length(j.product_id)>1024,false) OR coalesce(octet_length(r.product_id)>1024,false) OR
		       coalesce(octet_length(b.project_id)>1024,false) OR coalesce(octet_length(b.release_id)>1024,false) OR coalesce(octet_length(b.product_id)>1024,false) OR
		       coalesce(octet_length(d.release_id)>1024,false) OR coalesce(octet_length(d.product_id)>1024,false)
		FROM (SELECT 1) AS one
		LEFT JOIN tenants AS t ON t.id = $1
		LEFT JOIN products AS p ON p.id = $2 AND p.tenant_id = $1
		LEFT JOIN (projects AS j JOIN products AS jp ON jp.id=j.product_id AND jp.tenant_id=j.tenant_id) ON j.id = $3 AND j.tenant_id = $1
		LEFT JOIN (releases AS r JOIN products AS rp ON rp.id=r.product_id AND rp.tenant_id=r.tenant_id) ON r.id = $4 AND r.tenant_id = $1
		LEFT JOIN LATERAL (
		    SELECT run.project_id, run.release_id, project.product_id
		    FROM build_runs AS run
		    JOIN projects AS project ON project.id = run.project_id AND project.tenant_id = run.tenant_id
		    JOIN products AS product_owner ON product_owner.id=project.product_id AND product_owner.tenant_id=project.tenant_id
		    JOIN releases AS release ON release.id = run.release_id AND release.tenant_id = run.tenant_id
		        AND release.product_id = project.product_id
		    WHERE run.id = $5 AND run.tenant_id = $1
		) AS b ON true
		LEFT JOIN LATERAL (
		    SELECT deployment.release_id, environment.product_id
		    FROM deployment_events AS deployment
		    JOIN deployment_environments AS environment ON environment.id = deployment.environment_id
		        AND environment.tenant_id = deployment.tenant_id
		    JOIN products AS product_owner ON product_owner.id=environment.product_id AND product_owner.tenant_id=environment.tenant_id
		    JOIN releases AS release ON release.id = deployment.release_id
		        AND release.tenant_id = deployment.tenant_id AND release.product_id = environment.product_id
		    WHERE deployment.id = $6 AND deployment.tenant_id = $1
		) AS d ON true`, item.TenantID, item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID).Scan(
		&tenant, &product, &projectProduct, &releaseProduct,
		&buildProject, &buildRelease, &buildProduct, &deploymentRelease, &deploymentProduct, &oversized)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve evidence point scope: %w", err)
	}
	if oversized {
		return "", "", "", app.ErrConflict
	}
	if !tenant.Valid || item.ProductID != "" && !product.Valid || item.ProjectID != "" && !projectProduct.Valid ||
		item.ReleaseID != "" && !releaseProduct.Valid || item.BuildID != "" && !buildProduct.Valid ||
		item.DeploymentID != "" && !deploymentProduct.Valid {
		return "", "", "", evidencequery.ErrNotFound
	}
	if item.ProjectID != "" && item.BuildID != "" && item.ProjectID != buildProject.String ||
		item.ReleaseID != "" && item.BuildID != "" && item.ReleaseID != buildRelease.String ||
		item.ReleaseID != "" && item.DeploymentID != "" && item.ReleaseID != deploymentRelease.String ||
		item.BuildID != "" && item.DeploymentID != "" && buildRelease.String != deploymentRelease.String {
		return "", "", "", evidencequery.ErrNotFound
	}
	productID := ""
	for _, candidate := range []string{item.ProductID, projectProduct.String, releaseProduct.String, buildProduct.String, deploymentProduct.String} {
		if candidate == "" {
			continue
		}
		if productID != "" && productID != candidate {
			return "", "", "", evidencequery.ErrNotFound
		}
		productID = candidate
	}
	projectID := item.ProjectID
	if projectID == "" && item.BuildID != "" {
		projectID = buildProject.String
	}
	releaseID := item.ReleaseID
	if releaseID == "" && item.BuildID != "" {
		releaseID = buildRelease.String
	}
	if releaseID == "" && item.DeploymentID != "" {
		releaseID = deploymentRelease.String
	}
	return productID, projectID, releaseID, nil
}
