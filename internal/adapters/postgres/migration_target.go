package postgres

import (
	"context"
	"fmt"
	"strings"
)

// Check history on the owned runner session, before any application migration
// SQL. Query output is bounded by the expected catalog; no full history copy.
func (runner *migrationRunnerConnection) migrationTargetPrefix(ctx context.Context, table string, names []string) (int, error) {
	versions := make([]string, len(names))
	for i, name := range names {
		versions[i] = strings.TrimSuffix(name, ".up.sql")
	}
	var outside bool
	statement := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE version IS NULL OR NOT (version=ANY($1::text[])))`, table)
	if err := runner.connection.QueryRow(ctx, statement, versions).Scan(&outside); err != nil {
		return 0, fmt.Errorf("check target migration history: %w", err)
	}
	if outside {
		return 0, ErrMigrationHistory
	}
	statement = fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s applied WHERE applied.version=wanted.version) FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS wanted(version,position) ORDER BY wanted.position`, table)
	rows, err := runner.connection.Query(ctx, statement, versions)
	if err != nil {
		return 0, fmt.Errorf("read target migration prefix: %w", err)
	}
	defer rows.Close()
	prefix := 0
	missing := false
	for rows.Next() {
		var applied bool
		if err := rows.Scan(&applied); err != nil {
			return 0, fmt.Errorf("read target migration version: %w", err)
		}
		if applied {
			if missing {
				return 0, ErrMigrationHistory
			}
			prefix++
		} else {
			missing = true
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read target migration prefix: %w", err)
	}
	return prefix, nil
}
