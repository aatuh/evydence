package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.CollectorReader = (*Store)(nil)

const maxCollectorScopesBytes = 1 << 20

// PageCollectors reads one tenant-bound inventory page. The credential secret
// and hash are never selected; api_key_id is public collector metadata.
func (s *Store) PageCollectors(ctx context.Context, request integrationquery.CollectorPageRequest) (appquery.Result[integrationdomain.Collector], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[integrationdomain.Collector]{}, integrationquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	where, args, order, err := appendCreatedAtKeyset("c", []string{"c.tenant_id = $1"}, []any{request.TenantID}, request.Page, request.After)
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT c.id, c.tenant_id, c.name, c.type, c.version, c.api_key_id,
		       c.status, c.allowed_scopes, c.last_seen_at, c.schema_version, c.created_at
		FROM collectors AS c
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, fmt.Errorf("page collectors: %w", err)
	}
	defer rows.Close()
	items := make([]integrationdomain.Collector, 0, request.Page.PageSize+1)
	for rows.Next() {
		var collector integrationdomain.Collector
		var status string
		var scopes []byte
		var lastSeenAt sql.NullTime
		if err := rows.Scan(&collector.ID, &collector.TenantID, &collector.Name, &collector.Type,
			&collector.Version, &collector.APIKeyID, &status, &scopes, &lastSeenAt,
			&collector.SchemaVersion, &collector.CreatedAt); err != nil {
			return appquery.Result[integrationdomain.Collector]{}, fmt.Errorf("scan collector page: %w", err)
		}
		if len(scopes) > maxCollectorScopesBytes || json.Unmarshal(scopes, &collector.AllowedScopes) != nil {
			return appquery.Result[integrationdomain.Collector]{}, integrationquery.ErrInvalidProjection
		}
		collector.Status, err = integrationdomain.ParseCollectorStatus(status)
		if err != nil {
			return appquery.Result[integrationdomain.Collector]{}, integrationquery.ErrInvalidProjection
		}
		collector.LastSeenAt = nullableSQLTime(lastSeenAt)
		items = append(items, collector)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[integrationdomain.Collector]{}, fmt.Errorf("iterate collector page: %w", err)
	}
	result := appquery.Result[integrationdomain.Collector]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
