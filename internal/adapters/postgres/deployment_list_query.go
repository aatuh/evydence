package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.DeploymentListReader = (*Store)(nil)

// PageDeploymentEnvironments applies tenant ownership, verified product
// ownership, current actor visibility, filters, and keyset limit in SQL.
func (s *Store) PageDeploymentEnvironments(ctx context.Context, request operationsquery.EnvironmentPageRequest) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && len(request.AllowedProductIDs) != 0 || !request.TenantWide && len(request.AllowedProductIDs) == 0 {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	where := []string{"e.tenant_id = $1"}
	args := []any{request.TenantID}
	if request.ProductID != "" {
		args = append(args, request.ProductID)
		where = append(where, fmt.Sprintf("e.product_id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs)
		where = append(where, fmt.Sprintf("e.product_id = ANY($%d::text[])", len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("e", where, args, request.Page, request.After)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT e.id, e.tenant_id, e.product_id, e.name, e.kind, e.schema_version, e.created_at
		FROM deployment_environments AS e
		JOIN products AS p ON p.id = e.product_id AND p.tenant_id = e.tenant_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, fmt.Errorf("page deployment environments: %w", err)
	}
	defer rows.Close()
	items := make([]operationsdomain.DeploymentEnvironment, 0, request.Page.PageSize+1)
	for rows.Next() {
		var item operationsdomain.DeploymentEnvironment
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ProductID, &item.Name, &item.Kind, &item.SchemaVersion, &item.CreatedAt); err != nil {
			return appquery.Result[operationsdomain.DeploymentEnvironment]{}, fmt.Errorf("scan deployment environment page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, fmt.Errorf("iterate deployment environment page: %w", err)
	}
	result := appquery.Result[operationsdomain.DeploymentEnvironment]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		key := appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

// PageDeployments excludes dangling or cross-product parent relations before
// applying visibility and LIMIT. A single statement gives one database view.
func (s *Store) PageDeployments(ctx context.Context, request operationsquery.DeploymentPageRequest) (appquery.Result[operationsquery.DeploymentPoint], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return appquery.Result[operationsquery.DeploymentPoint]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[operationsquery.DeploymentPoint]{}, err
	}
	where := []string{"d.tenant_id = $1"}
	args := []any{request.TenantID}
	if request.ReleaseID != "" {
		args = append(args, request.ReleaseID)
		where = append(where, fmt.Sprintf("d.release_id = $%d", len(args)))
	}
	if request.EnvironmentID != "" {
		args = append(args, request.EnvironmentID)
		where = append(where, fmt.Sprintf("d.environment_id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs, request.AllowedReleaseIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR d.release_id = ANY($%d::text[]))", len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("d", where, args, request.Page, request.After)
	if err != nil {
		return appquery.Result[operationsquery.DeploymentPoint]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT d.id, d.tenant_id, d.environment_id, d.release_id, d.artifact_ids,
		       d.status, d.started_at, d.finished_at, d.rollback_of, d.evidence_id,
		       d.schema_version, d.created_at, p.id
		FROM deployment_events AS d
		JOIN deployment_environments AS e ON e.id = d.environment_id AND e.tenant_id = d.tenant_id
		JOIN releases AS r ON r.id = d.release_id AND r.tenant_id = d.tenant_id AND r.product_id = e.product_id
		JOIN products AS p ON p.id = e.product_id AND p.tenant_id = d.tenant_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[operationsquery.DeploymentPoint]{}, fmt.Errorf("page deployments: %w", err)
	}
	defer rows.Close()
	items := make([]operationsquery.DeploymentPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point operationsquery.DeploymentPoint
		var finishedAt sql.NullTime
		var rollbackOf, evidenceID sql.NullString
		item := &point.Deployment
		if err := rows.Scan(&item.ID, &item.TenantID, &item.EnvironmentID, &item.ReleaseID, &item.ArtifactIDs,
			&item.Status, &item.StartedAt, &finishedAt, &rollbackOf, &evidenceID,
			&item.SchemaVersion, &item.CreatedAt, &point.ProductID); err != nil {
			return appquery.Result[operationsquery.DeploymentPoint]{}, fmt.Errorf("scan deployment page: %w", err)
		}
		item.FinishedAt = nullableSQLTime(finishedAt)
		item.RollbackOf = nullableSQLString(rollbackOf)
		item.EvidenceID = nullableSQLString(evidenceID)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[operationsquery.DeploymentPoint]{}, fmt.Errorf("iterate deployment page: %w", err)
	}
	result := appquery.Result[operationsquery.DeploymentPoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Deployment
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
