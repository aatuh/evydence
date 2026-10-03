package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.SourceRepositoryReader = (*Store)(nil)

// PageSourceRepositories applies the tenant, current project/product parent,
// actor visibility, and cursor limit in one PostgreSQL statement. Detached
// legacy repositories remain visible to tenant-wide actors only.
func (s *Store) PageSourceRepositories(ctx context.Context, request integrationquery.SourceRepositoryPageRequest) (appquery.Result[integrationquery.SourceRepositoryPoint], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedProjectIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedProjectIDs) == 0 {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, err
	}
	where := []string{"s.tenant_id = $1", "(s.project_id IS NULL OR p.id IS NOT NULL)"}
	args := []any{request.TenantID}
	if request.ProjectID != "" {
		args = append(args, request.ProjectID)
		where = append(where, fmt.Sprintf("s.project_id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs, request.AllowedProjectIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR s.project_id = ANY($%d::text[]))", len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("s", where, args, request.Page, request.After)
	if err != nil {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT s.id, s.tenant_id, s.project_id, s.provider, s.full_name,
		       s.clone_url, s.default_branch, s.schema_version, s.created_at, p.id
		FROM source_repositories AS s
		LEFT JOIN projects AS j ON j.id = s.project_id AND j.tenant_id = s.tenant_id
		LEFT JOIN products AS p ON p.id = j.product_id AND p.tenant_id = s.tenant_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, fmt.Errorf("page source repositories: %w", err)
	}
	defer rows.Close()
	items := make([]integrationquery.SourceRepositoryPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point integrationquery.SourceRepositoryPoint
		var projectID, cloneURL, defaultBranch, productID sql.NullString
		item := &point.Repository
		if err := rows.Scan(&item.ID, &item.TenantID, &projectID, &item.Provider, &item.FullName,
			&cloneURL, &defaultBranch, &item.SchemaVersion, &item.CreatedAt, &productID); err != nil {
			return appquery.Result[integrationquery.SourceRepositoryPoint]{}, fmt.Errorf("scan source repository page: %w", err)
		}
		item.ProjectID = nullableSQLString(projectID)
		item.CloneURL = nullableSQLString(cloneURL)
		item.DefaultBranch = nullableSQLString(defaultBranch)
		point.ProductID = nullableSQLString(productID)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, fmt.Errorf("iterate source repository page: %w", err)
	}
	result := appquery.Result[integrationquery.SourceRepositoryPoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Repository
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
