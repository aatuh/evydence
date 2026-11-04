package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Immutable operational expectations only; no migration identity is exported.
type migrationExpectations struct{ versions []string }

func (s *Store) recordMigrationExpectations(names []string) {
	if s == nil {
		return
	}
	versions := make([]string, len(names))
	for i, name := range names {
		versions[i] = strings.TrimSuffix(name, ".up.sql")
	}
	s.migrationVersions.Store(&migrationExpectations{versions: versions})
}

func (s *Store) ApplyMigrations(ctx context.Context, dir string) (int, error) {
	catalog, err := loadMigrationCatalog(ctx, dir)
	if err != nil {
		if s != nil {
			s.migrationVersions.Store(nil)
		}
		return 0, err
	}
	return s.applyMigrationCatalog(ctx, catalog, false, true, "")
}

func (s *Store) applyMigrationCatalog(ctx context.Context, catalog []migrationScript, requirePrefix, allowLegacy bool, runtimeRole string) (applied int, resultErr error) {
	names := make([]string, len(catalog))
	for i, script := range catalog {
		names[i] = script.name
	}
	s.recordMigrationExpectations(names)
	runner, err := s.acquireMigrationRunner(ctx)
	if err != nil {
		return 0, err
	}
	execution := migrationExecution{runner: runner, runtimeRole: runtimeRole}
	if len(catalog) > 0 {
		execution.target = strings.TrimSuffix(catalog[len(catalog)-1].name, ".up.sql")
	}
	defer func() { resultErr = errors.Join(resultErr, execution.close(ctx, resultErr, applied)) }()
	if err := execution.validate(ctx); err != nil {
		return 0, err
	}
	table := pgx.Identifier{runner.schema, "schema_migrations"}.Sanitize()
	if _, err := runner.connection.Exec(ctx, fmt.Sprintf(createSchemaMigrationsTableSQL, table)); err != nil {
		return 0, fmt.Errorf("ensure schema migrations table: %w", err)
	}
	if _, err := runner.connection.Exec(ctx, fmt.Sprintf(migrationMetadataColumnsSQL, table)); err != nil {
		return 0, fmt.Errorf("expand migration execution metadata: %w", err)
	}
	if err := execution.start(ctx); err != nil {
		return 0, err
	}
	existing, err := runner.migrationExecutionHistory(ctx, table, catalog, requirePrefix, allowLegacy)
	if err != nil {
		return 0, err
	}
	for i, script := range catalog {
		version := strings.TrimSuffix(script.name, ".up.sql")
		if existing[i] {
			continue
		}
		tx, err := runner.connection.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return applied, fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, script.body); err != nil {
			execution.rollback(ctx, tx)
			return applied, fmt.Errorf("apply migration %s: %w", version, err)
		}
		record := fmt.Sprintf(`INSERT INTO %s (version,checksum_sha256,applied_by) VALUES ($1,$2,session_user)`, table)
		if _, err := tx.Exec(ctx, record, version, migrationChecksum(script.body)); err != nil {
			execution.rollback(ctx, tx)
			return applied, fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			execution.uncertain = true
			return applied, fmt.Errorf("commit migration %s: %w", version, err)
		}
		applied++
	}
	if err := execution.complete(ctx, applied); err != nil {
		return applied, err
	}
	return applied, nil
}

func (s *Store) PendingMigrationVersions(ctx context.Context, dir string) ([]string, error) {
	return s.pendingMigrationVersions(ctx, dir, false)
}

func (s *Store) pendingMigrationVersions(ctx context.Context, dir string, runtimeReady bool) (pending []string, resultErr error) {
	names, err := migrationNamesContext(ctx, dir)
	if err != nil {
		if s != nil {
			s.migrationVersions.Store(nil)
		}
		return nil, err
	}
	s.recordMigrationExpectations(names)
	reader, finish, err := s.migrationStateView(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := finish(); err != nil {
			pending = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()
	versions := make([]string, len(names))
	for i, name := range names {
		versions[i] = strings.TrimSuffix(name, ".up.sql")
	}
	table := pgx.Identifier{reader.schema, "schema_migrations"}.Sanitize()
	var exists bool
	if err := reader.connection.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check migration tracking table: %w", err)
	}
	if !exists {
		if runtimeReady && len(versions) == 0 {
			if err := reader.checkMigrationOperationReady(ctx, ""); err != nil {
				return nil, err
			}
		}
		return versions, nil
	}
	// Only the quoted identifier is SQL text. All versions are bound values;
	// ordinality preserves catalog order and bounds output by the input list.
	statement := fmt.Sprintf(`SELECT wanted.version FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS wanted(version,position) WHERE NOT EXISTS (SELECT 1 FROM %s applied WHERE applied.version=wanted.version) ORDER BY wanted.position`, table)
	rows, err := reader.connection.Query(ctx, statement, versions)
	if err != nil {
		return nil, fmt.Errorf("read pending migration versions: %w", err)
	}
	defer rows.Close()
	pending = []string{}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("read pending migration version: %w", err)
		}
		pending = append(pending, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read pending migration versions: %w", err)
	}
	rows.Close()
	if runtimeReady && len(pending) == 0 {
		target := ""
		if len(versions) > 0 {
			target = versions[len(versions)-1]
		}
		if err := reader.checkMigrationOperationReady(ctx, target); err != nil {
			return nil, err
		}
	}
	return pending, nil
}

func (s *Store) RequireNoPendingMigrations(ctx context.Context, dir string) error {
	return s.requireNoPendingMigrations(ctx, dir, false)
}

func (s *Store) requireNoPendingMigrations(ctx context.Context, dir string, runtimeReady bool) error {
	pending, err := s.pendingMigrationVersions(ctx, dir, runtimeReady)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("database has %d unapplied migration(s); first pending migration is %s", len(pending), pending[0])
	}
	return nil
}

const createSchemaMigrationsTableSQL = `
		CREATE TABLE IF NOT EXISTS %s (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`

// Operational tracking expands before executing application migrations, just
// like its initial table bootstrap. The committed migration declares the same
// additive shape for older runners. Existing rows remain null, never backfilled.
const migrationMetadataColumnsSQL = `ALTER TABLE %s
 ADD COLUMN IF NOT EXISTS checksum_sha256 text
  CHECK (checksum_sha256 IS NULL OR checksum_sha256 ~ '^[0-9a-f]{64}$'),
 ADD COLUMN IF NOT EXISTS applied_by name
  CHECK ((checksum_sha256 IS NULL) = (applied_by IS NULL))`
