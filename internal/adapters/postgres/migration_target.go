package postgres

import (
	"context"
	"fmt"
	"strings"
)

// Check history on the owned runner session, before any application migration
// SQL. Query output is bounded by the expected catalog; no full history copy.
func (runner *migrationRunnerConnection) migrationExecutionHistory(ctx context.Context, table string, catalog []migrationScript, requirePrefix, allowLegacy bool) ([]bool, error) {
	versions := make([]string, len(catalog))
	for i, script := range catalog {
		versions[i] = strings.TrimSuffix(script.name, ".up.sql")
	}
	if requirePrefix {
		var outside bool
		statement := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE version IS NULL OR NOT (version=ANY($1::text[])))`, table)
		if err := runner.connection.QueryRow(ctx, statement, versions).Scan(&outside); err != nil {
			return nil, fmt.Errorf("check target migration history: %w", err)
		}
		if outside {
			return nil, ErrMigrationHistory
		}
	}
	statement := fmt.Sprintf(`SELECT applied.version IS NOT NULL,applied.checksum_sha256,applied.applied_by::text FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS wanted(version,position) LEFT JOIN %s applied ON applied.version=wanted.version ORDER BY wanted.position`, table)
	rows, err := runner.connection.Query(ctx, statement, versions)
	if err != nil {
		return nil, fmt.Errorf("read migration execution history: %w", err)
	}
	defer rows.Close()
	existing := make([]bool, len(catalog))
	position := 0
	missing := false
	legacy := false
	for rows.Next() {
		var applied bool
		var checksum, principal *string
		if err := rows.Scan(&applied, &checksum, &principal); err != nil {
			return nil, fmt.Errorf("read migration execution record: %w", err)
		}
		if position >= len(existing) {
			return nil, ErrMigrationHistory
		}
		if applied {
			if requirePrefix && missing {
				return nil, ErrMigrationHistory
			}
			if (checksum == nil) != (principal == nil) {
				return nil, ErrMigrationHistory
			}
			if checksum == nil {
				legacy = true
			} else if *checksum != migrationChecksum(catalog[position].body) {
				return nil, ErrMigrationChecksum
			}
			existing[position] = true
		} else {
			missing = true
		}
		position++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migration execution history: %w", err)
	}
	if position != len(existing) {
		return nil, ErrMigrationHistory
	}
	if legacy && !allowLegacy {
		return nil, ErrMigrationLegacyHistory
	}
	return existing, nil
}
