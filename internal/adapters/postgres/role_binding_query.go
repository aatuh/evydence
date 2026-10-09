package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

var _ identityquery.RoleBindingReader = (*Store)(nil)

// PageRoleBindings applies tenant ownership, keyset, and limit in PostgreSQL.
// It reads the current role-binding rows; it does not infer grants from the
// API's transitional Ledger snapshot.
func (s *Store) PageRoleBindings(ctx context.Context, request identityquery.RoleBindingPageRequest) (appquery.Result[identitydomain.RoleBinding], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[identitydomain.RoleBinding]{}, identityquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	where := []string{"tenant_id = $1"}
	args := []any{request.TenantID}
	operator, direction := ">", "ASC"
	if request.Page.Direction == appquery.Descending {
		operator, direction = "<", "DESC"
	}
	order := "created_at " + direction + ", id " + direction
	switch request.Page.Sort {
	case appquery.SortCreatedAt:
		if request.After != nil {
			createdAt, err := time.Parse(time.RFC3339Nano, request.After.Value)
			if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != request.After.Value {
				return appquery.Result[identitydomain.RoleBinding]{}, appquery.ErrInvalidCursor
			}
			args = append(args, createdAt, request.After.ID)
			where = append(where, fmt.Sprintf("(created_at %s $%d OR (created_at = $%d AND id %s $%d))", operator, len(args)-1, len(args)-1, operator, len(args)))
		}
	case appquery.SortID:
		order = "id " + direction
		if request.After != nil {
			if request.After.Value != request.After.ID {
				return appquery.Result[identitydomain.RoleBinding]{}, appquery.ErrInvalidCursor
			}
			args = append(args, request.After.ID)
			where = append(where, fmt.Sprintf("id %s $%d", operator, len(args)))
		}
	default:
		return appquery.Result[identitydomain.RoleBinding]{}, appquery.ErrInvalidPage
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT id, tenant_id, subject_type, subject_id, role, resource_type,
		       resource_id, schema_version, created_at
		FROM role_bindings WHERE %s
		ORDER BY %s LIMIT $%d`, strings.Join(where, " AND "), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, fmt.Errorf("page role bindings: %w", err)
	}
	defer rows.Close()
	items := make([]identitydomain.RoleBinding, 0, request.Page.PageSize+1)
	for rows.Next() {
		var binding identitydomain.RoleBinding
		var resourceType, resourceID sql.NullString
		if err := rows.Scan(&binding.ID, &binding.TenantID, &binding.SubjectType,
			&binding.SubjectID, &binding.Role, &resourceType, &resourceID,
			&binding.SchemaVersion, &binding.CreatedAt); err != nil {
			return appquery.Result[identitydomain.RoleBinding]{}, fmt.Errorf("scan role-binding page: %w", err)
		}
		binding.ResourceType = nullableSQLString(resourceType)
		binding.ResourceID = nullableSQLString(resourceID)
		items = append(items, binding)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, fmt.Errorf("page role bindings: %w", err)
	}
	result := appquery.Result[identitydomain.RoleBinding]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
