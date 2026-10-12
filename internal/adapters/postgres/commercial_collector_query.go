package postgres

import (
	"context"
	"fmt"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.CommercialCollectorReader = (*Store)(nil)

// PageCommercialCollectors applies the tenant and keyset limit in SQL.
func (s *Store) PageCommercialCollectors(ctx context.Context, request integrationquery.CommercialCollectorPageRequest) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	var empty appquery.Result[integrationdomain.CommercialCollectorDefinition]
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return empty, integrationquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, err
	}
	where, args, order, err := appendCreatedAtKeyset("c", []string{"c.tenant_id = $1"}, []any{request.TenantID}, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT c.id, c.tenant_id, c.name, c.provider, c.version,
		       c.manifest_hash, c.allowed_scopes, c.status, c.schema_version, c.created_at
		FROM commercial_collectors AS c
		WHERE %s
		ORDER BY %s LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page commercial collectors: %w", err)
	}
	defer rows.Close()
	items := make([]integrationdomain.CommercialCollectorDefinition, 0, request.Page.PageSize+1)
	for rows.Next() {
		var definition integrationdomain.CommercialCollectorDefinition
		if err := rows.Scan(&definition.ID, &definition.TenantID, &definition.Name,
			&definition.Provider, &definition.Version, &definition.ManifestHash,
			&definition.AllowedScopes, &definition.Status, &definition.SchemaVersion,
			&definition.CreatedAt); err != nil {
			return empty, fmt.Errorf("scan commercial collector page: %w", err)
		}
		items = append(items, definition)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate commercial collector page: %w", err)
	}
	result := appquery.Result[integrationdomain.CommercialCollectorDefinition]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
