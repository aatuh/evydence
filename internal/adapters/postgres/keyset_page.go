package postgres

import (
	"fmt"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
)

// appendCreatedAtKeyset accepts only adapter-owned SQL aliases, never client input.
func appendCreatedAtKeyset(alias string, where []string, args []any, page appquery.PageRequest, after *appquery.SortKey) ([]string, []any, string, error) {
	operator, direction := ">", "ASC"
	if page.Direction == appquery.Descending {
		operator, direction = "<", "DESC"
	}
	order := alias + ".created_at " + direction + ", " + alias + ".id " + direction
	switch page.Sort {
	case appquery.SortCreatedAt:
		if after != nil {
			createdAt, err := time.Parse(time.RFC3339Nano, after.Value)
			if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != after.Value {
				return nil, nil, "", appquery.ErrInvalidCursor
			}
			args = append(args, createdAt, after.ID)
			where = append(where, fmt.Sprintf("(%s.created_at %s $%d OR (%s.created_at = $%d AND %s.id %s $%d))", alias, operator, len(args)-1, alias, len(args)-1, alias, operator, len(args)))
		}
	case appquery.SortID:
		order = alias + ".id " + direction
		if after != nil {
			if after.Value != after.ID {
				return nil, nil, "", appquery.ErrInvalidCursor
			}
			args = append(args, after.ID)
			where = append(where, fmt.Sprintf("%s.id %s $%d", alias, operator, len(args)))
		}
	default:
		return nil, nil, "", appquery.ErrInvalidPage
	}
	return where, args, order, nil
}
