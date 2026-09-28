package postgres

import (
	"context"
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
