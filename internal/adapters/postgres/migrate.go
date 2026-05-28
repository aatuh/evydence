package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Store) ApplyMigrations(ctx context.Context, dir string) (int, error) {
	names, err := migrationNames(dir)
	if err != nil {
		return 0, err
	}
	if err := s.ensureSchemaMigrationsTable(ctx); err != nil {
		return 0, err
	}
	applied := 0
	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")
		var exists bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists)
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
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return applied, fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`, version); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit migration %s: %w", version, err)
		}
		applied++
	}
	return applied, nil
}

func (s *Store) PendingMigrationVersions(ctx context.Context, dir string) ([]string, error) {
	names, err := migrationNames(dir)
	if err != nil {
		return nil, err
	}
	if err := s.ensureSchemaMigrationsTable(ctx); err != nil {
		return nil, err
	}
	pending := []string{}
	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")
		var exists bool
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("check migration %s: %w", version, err)
		}
		if !exists {
			pending = append(pending, version)
		}
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

func (s *Store) ensureSchemaMigrationsTable(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("ensure schema migrations table: %w", err)
	}
	return nil
}

func migrationNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
