package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.DeploymentPointReader = (*Store)(nil)

// GetDeploymentPoint verifies the tenant, release, environment, and shared
// product in one statement before returning authorization coordinates.
func (s *Store) GetDeploymentPoint(ctx context.Context, tenantID, id string) (operationsquery.DeploymentPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return operationsquery.DeploymentPoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return operationsquery.DeploymentPoint{}, operationsquery.ErrNotFound
	}
	var point operationsquery.DeploymentPoint
	var finishedAt sql.NullTime
	var rollbackOf, evidenceID sql.NullString
	err := s.pool.QueryRow(ctx, `
		SELECT d.id, d.tenant_id, d.environment_id, d.release_id, d.artifact_ids,
		       d.status, d.started_at, d.finished_at, d.rollback_of, d.evidence_id,
		       d.schema_version, d.created_at, p.id
		FROM deployment_events AS d
		JOIN deployment_environments AS e ON e.id = d.environment_id AND e.tenant_id = d.tenant_id
		JOIN releases AS r ON r.id = d.release_id AND r.tenant_id = d.tenant_id
		    AND r.product_id = e.product_id
		JOIN products AS p ON p.id = e.product_id AND p.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1 AND d.id = $2`, tenantID, id).Scan(
		&point.Deployment.ID, &point.Deployment.TenantID,
		&point.Deployment.EnvironmentID, &point.Deployment.ReleaseID,
		&point.Deployment.ArtifactIDs, &point.Deployment.Status,
		&point.Deployment.StartedAt, &finishedAt, &rollbackOf, &evidenceID,
		&point.Deployment.SchemaVersion, &point.Deployment.CreatedAt, &point.ProductID)
	if errors.Is(err, pgx.ErrNoRows) {
		return operationsquery.DeploymentPoint{}, operationsquery.ErrNotFound
	}
	if err != nil {
		return operationsquery.DeploymentPoint{}, fmt.Errorf("get deployment point: %w", err)
	}
	point.Deployment.FinishedAt = nullableSQLTime(finishedAt)
	point.Deployment.RollbackOf = nullableSQLString(rollbackOf)
	point.Deployment.EvidenceID = nullableSQLString(evidenceID)
	return point, nil
}
