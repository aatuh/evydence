package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

var _ identityquery.APIKeyReader = (*Store)(nil)

const maxAPIKeyScopesBytes = 1 << 20

// PageAPIKeys returns only public metadata. The credential hash is deliberately
// absent from the SELECT list and cannot enter the query result.
func (s *Store) PageAPIKeys(ctx context.Context, request identityquery.APIKeyPageRequest) (appquery.Result[identitydomain.APIKey], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[identitydomain.APIKey]{}, identityquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
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
				return appquery.Result[identitydomain.APIKey]{}, appquery.ErrInvalidCursor
			}
			args = append(args, createdAt, request.After.ID)
			where = append(where, fmt.Sprintf("(created_at %s $%d OR (created_at = $%d AND id %s $%d))", operator, len(args)-1, len(args)-1, operator, len(args)))
		}
	case appquery.SortID:
		order = "id " + direction
		if request.After != nil {
			if request.After.Value != request.After.ID {
				return appquery.Result[identitydomain.APIKey]{}, appquery.ErrInvalidCursor
			}
			args = append(args, request.After.ID)
			where = append(where, fmt.Sprintf("id %s $%d", operator, len(args)))
		}
	default:
		return appquery.Result[identitydomain.APIKey]{}, appquery.ErrInvalidPage
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT id, tenant_id, name, prefix, scopes, expires_at, revoked_at,
		       last_used_at, created_at
		FROM api_keys WHERE %s
		ORDER BY %s LIMIT $%d`, strings.Join(where, " AND "), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, fmt.Errorf("page API keys: %w", err)
	}
	defer rows.Close()
	items := make([]identitydomain.APIKey, 0, request.Page.PageSize+1)
	for rows.Next() {
		var key identitydomain.APIKey
		var scopes []byte
		var expiresAt, revokedAt, lastUsedAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Name, &key.Prefix, &scopes,
			&expiresAt, &revokedAt, &lastUsedAt, &key.CreatedAt); err != nil {
			return appquery.Result[identitydomain.APIKey]{}, fmt.Errorf("scan API-key page: %w", err)
		}
		if len(scopes) > maxAPIKeyScopesBytes {
			return appquery.Result[identitydomain.APIKey]{}, errors.New("oversized stored API-key scopes")
		}
		if err := json.Unmarshal(scopes, &key.Scopes); err != nil || len(key.Scopes) == 0 {
			return appquery.Result[identitydomain.APIKey]{}, errors.New("invalid stored API-key scopes")
		}
		key.ExpiresAt = nullableSQLTime(expiresAt)
		key.RevokedAt = nullableSQLTime(revokedAt)
		key.LastUsedAt = nullableSQLTime(lastUsedAt)
		items = append(items, key)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[identitydomain.APIKey]{}, fmt.Errorf("page API keys: %w", err)
	}
	result := appquery.Result[identitydomain.APIKey]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
