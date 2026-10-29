package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

func (s *Store) ApplyMigrations(ctx context.Context, dir string) (applied int, resultErr error) {
	names, err := migrationNames(dir)
	if err != nil {
		if s != nil {
			s.migrationVersions.Store(nil)
		}
		return 0, err
	}
	s.recordMigrationExpectations(names)
	runner, err := s.acquireMigrationRunner(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, runner.release(ctx)) }()
	if _, err := runner.connection.Exec(ctx, createSchemaMigrationsTableSQL); err != nil {
		return 0, fmt.Errorf("ensure schema migrations table: %w", err)
	}
	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")
		var exists bool
		err := runner.connection.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists)
		if err != nil {
			return applied, fmt.Errorf("check migration %s: %w", version, err)
		}
		if exists {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- name comes from ReadDir and is filtered to .up.sql files.
		if err != nil {
			return applied, fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := runner.connection.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return applied, fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			rollbackMigration(ctx, tx)
			return applied, fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`, version); err != nil {
			rollbackMigration(ctx, tx)
			return applied, fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit migration %s: %w", version, err)
		}
		applied++
	}
	return applied, nil
}

func rollbackMigration(ctx context.Context, tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}

func (s *Store) PendingMigrationVersions(ctx context.Context, dir string) (pending []string, resultErr error) {
	names, err := migrationNames(dir)
	if err != nil {
		if s != nil {
			s.migrationVersions.Store(nil)
		}
		return nil, err
	}
	s.recordMigrationExpectations(names)
	reader, err := s.acquireMigrationStateReader(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := reader.release(ctx); err != nil {
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
	return pending, nil
}

func (s *Store) RequireNoPendingMigrations(ctx context.Context, dir string) error {
	pending, err := s.PendingMigrationVersions(ctx, dir)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("database has %d unapplied migration(s); first pending migration is %s", len(pending), pending[0])
	}
	return nil
}

const createSchemaMigrationsTableSQL = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`

func migrationNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	names := []string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, errors.New("read migration file metadata")
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("migration up files must be regular files")
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
