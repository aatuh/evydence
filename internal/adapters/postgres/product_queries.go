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
	appquery "github.com/aatuh/evydence/internal/app/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// GetProject requires both the project and its parent product to belong to
// the requested tenant. The join prevents a mismatched foreign key from
// becoming a visible cross-tenant projection.
func (s *Store) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return releasedomain.Project{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Project{}, releasequery.ErrNotFound
	}
	var project releasedomain.Project
	err := s.pool.QueryRow(ctx, `
		SELECT j.id, j.tenant_id, j.product_id, j.name, j.created_at
		FROM projects AS j
		JOIN products AS p ON p.id = j.product_id AND p.tenant_id = j.tenant_id
		WHERE j.tenant_id = $1 AND j.id = $2`, tenantID, id).
		Scan(&project.ID, &project.TenantID, &project.ProductID, &project.Name, &project.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.Project{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasedomain.Project{}, fmt.Errorf("get project: %w", err)
	}
	return project, nil
}

// GetRelease reads the release and its tenant-bound parent in one statement.
func (s *Store) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return releasedomain.Release{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Release{}, releasequery.ErrNotFound
	}
	var release releasedomain.Release
	var state string
	var frozenAt, approvedAt sql.NullTime
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.tenant_id, r.product_id, r.version, r.state,
		       r.frozen_at, r.approved_at, r.revision, r.created_at
		FROM releases AS r
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND r.id = $2`, tenantID, id).
		Scan(&release.ID, &release.TenantID, &release.ProductID, &release.Version,
			&state, &frozenAt, &approvedAt, &release.Revision, &release.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.Release{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasedomain.Release{}, fmt.Errorf("get release: %w", err)
	}
	release.State, err = releasedomain.ParseReleaseState(state)
	if err != nil {
		return releasedomain.Release{}, fmt.Errorf("get release state: %w", err)
	}
	release.FrozenAt = nullableSQLTime(frozenAt)
	release.ApprovedAt = nullableSQLTime(approvedAt)
	return release, nil
}

// GetProduct scopes the point read in SQL before a product can be authorized
// or returned by the application query service.
func (s *Store) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return releasedomain.Product{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Product{}, releasequery.ErrNotFound
	}
	var product releasedomain.Product
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, slug, created_at
		FROM products
		WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&product.ID, &product.TenantID, &product.Name, &product.Slug, &product.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.Product{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasedomain.Product{}, fmt.Errorf("get product: %w", err)
	}
	return product, nil
}

// PageProducts performs the visibility filter and keyset limit in one SQL
// statement, so all returned product rows are from one PostgreSQL snapshot.
// No tenant-wide product slice or process cache is consulted.
func (s *Store) PageProducts(ctx context.Context, request releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[releasedomain.Product]{}, app.ErrValidation
	}
	if !request.TenantWide && len(request.AllowedProductIDs) == 0 {
		return appquery.Result[releasedomain.Product]{}, app.ErrValidation
	}
	if request.TenantWide && len(request.AllowedProductIDs) != 0 {
		return appquery.Result[releasedomain.Product]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	where := []string{"tenant_id = $1"}
	args := []any{request.TenantID}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs)
		where = append(where, fmt.Sprintf("id = ANY($%d::text[])", len(args)))
	}
	operator := ">"
	if request.Page.Direction == appquery.Descending {
		operator = "<"
	}
	order := "created_at ASC, id ASC"
	if request.Page.Direction == appquery.Descending {
		order = "created_at DESC, id DESC"
	}
	switch request.Page.Sort {
	case appquery.SortCreatedAt:
		if request.After != nil {
			createdAt, err := time.Parse(time.RFC3339Nano, request.After.Value)
			if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != request.After.Value {
				return appquery.Result[releasedomain.Product]{}, appquery.ErrInvalidCursor
			}
			args = append(args, createdAt, request.After.ID)
			where = append(where, fmt.Sprintf("(created_at %s $%d OR (created_at = $%d AND id %s $%d))", operator, len(args)-1, len(args)-1, operator, len(args)))
		}
	case appquery.SortID:
		order = "id ASC"
		if request.Page.Direction == appquery.Descending {
			order = "id DESC"
		}
		if request.After != nil {
			if request.After.Value != request.After.ID {
				return appquery.Result[releasedomain.Product]{}, appquery.ErrInvalidCursor
			}
			args = append(args, request.After.ID)
			where = append(where, fmt.Sprintf("id %s $%d", operator, len(args)))
		}
	default:
		return appquery.Result[releasedomain.Product]{}, appquery.ErrInvalidPage
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT id, tenant_id, name, slug, created_at
		FROM products
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, strings.Join(where, " AND "), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, fmt.Errorf("page products: %w", err)
	}
	defer rows.Close()
	items := make([]releasedomain.Product, 0, request.Page.PageSize+1)
	for rows.Next() {
		var product releasedomain.Product
		if err := rows.Scan(&product.ID, &product.TenantID, &product.Name, &product.Slug, &product.CreatedAt); err != nil {
			return appquery.Result[releasedomain.Product]{}, fmt.Errorf("scan product page: %w", err)
		}
		items = append(items, product)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[releasedomain.Product]{}, fmt.Errorf("iterate product page: %w", err)
	}
	result := appquery.Result[releasedomain.Product]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		key := appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
