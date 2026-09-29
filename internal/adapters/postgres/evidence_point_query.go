package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePointReader = (*Store)(nil)

// GetEvidencePoint reads one tenant-owned evidence row and validates all
// populated parent coordinates in a stable PostgreSQL snapshot. Worker-owned
// evidence still requires the compatibility projection's provenance checks.
func (s *Store) GetEvidencePoint(ctx context.Context, tenantID, id string) (evidencequery.EvidencePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return evidencequery.EvidencePoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.EvidencePoint{}, evidencequery.ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return evidencequery.EvidencePoint{}, fmt.Errorf("begin evidence point snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	item, err := loadParserReplayEvidence(ctx, tx, tenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.EvidencePoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	if evidencedomain.RequiresWorkerProjection(item.Type) {
		return evidencequery.EvidencePoint{}, evidencequery.ErrRequiresProjection
	}
	productID, projectID, releaseID, err := resolveEvidencePointScope(ctx, tx, item)
	if err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	return evidencequery.EvidencePoint{
		Item: domain.EvidenceToContextModel(item), ProductID: productID,
		ProjectID: projectID, ReleaseID: releaseID,
	}, nil
}

func resolveEvidencePointScope(ctx context.Context, tx pgx.Tx, item domain.EvidenceItem) (string, string, string, error) {
	var tenant, product, projectProduct, releaseProduct sql.NullString
	var buildProject, buildRelease, buildProduct sql.NullString
	var deploymentRelease, deploymentProduct sql.NullString
	err := tx.QueryRow(ctx, `
		SELECT t.id, p.id, j.product_id, r.product_id,
		       b.project_id, b.release_id, b.product_id,
		       d.release_id, d.product_id
		FROM (SELECT 1) AS one
		LEFT JOIN tenants AS t ON t.id = $1
		LEFT JOIN products AS p ON p.id = $2 AND p.tenant_id = $1
		LEFT JOIN projects AS j ON j.id = $3 AND j.tenant_id = $1
		LEFT JOIN releases AS r ON r.id = $4 AND r.tenant_id = $1
		LEFT JOIN LATERAL (
		    SELECT run.project_id, run.release_id, project.product_id
		    FROM build_runs AS run
		    JOIN projects AS project ON project.id = run.project_id AND project.tenant_id = run.tenant_id
		    JOIN releases AS release ON release.id = run.release_id AND release.tenant_id = run.tenant_id
		        AND release.product_id = project.product_id
		    WHERE run.id = $5 AND run.tenant_id = $1
		) AS b ON true
		LEFT JOIN LATERAL (
		    SELECT deployment.release_id, environment.product_id
		    FROM deployment_events AS deployment
		    JOIN deployment_environments AS environment ON environment.id = deployment.environment_id
		        AND environment.tenant_id = deployment.tenant_id
		    JOIN releases AS release ON release.id = deployment.release_id
		        AND release.tenant_id = deployment.tenant_id AND release.product_id = environment.product_id
		    WHERE deployment.id = $6 AND deployment.tenant_id = $1
		) AS d ON true`, item.TenantID, item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID).Scan(
		&tenant, &product, &projectProduct, &releaseProduct,
		&buildProject, &buildRelease, &buildProduct, &deploymentRelease, &deploymentProduct)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve evidence point scope: %w", err)
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
