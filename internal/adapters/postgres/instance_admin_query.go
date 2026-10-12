package postgres

import (
	"context"
	"fmt"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.InstanceCountsReader = (*Store)(nil)

// ReadInstanceCounts returns one database snapshot of global cardinalities.
// No tenant rows, payloads, or credential material are loaded into the API.
func (s *Store) ReadInstanceCounts(ctx context.Context) (operationsquery.InstanceCounts, error) {
	var empty operationsquery.InstanceCounts
	if s == nil || s.pool == nil || ctx == nil {
		return empty, operationsquery.ErrValidation
	}
	var tenants, users, collectors, evidence int64
	err := s.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM tenants),
		       (SELECT count(*) FROM human_users),
		       (SELECT count(*) FROM collectors),
		       (SELECT count(*) FROM evidence_items)`).Scan(&tenants, &users, &collectors, &evidence)
	if err != nil {
		return empty, fmt.Errorf("read instance counts: %w", err)
	}
	maxInt := int64(^uint(0) >> 1)
	if tenants > maxInt || users > maxInt || collectors > maxInt || evidence > maxInt {
		return empty, operationsquery.ErrInvalidProjection
	}
	return operationsquery.InstanceCounts{Tenants: int(tenants), Users: int(users), Collectors: int(collectors), Evidence: int(evidence)}, nil
}
