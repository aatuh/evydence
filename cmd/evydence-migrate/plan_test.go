package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
)

func TestMigrationCommandPreflightsPlanBeforeOpeningDatabase(t *testing.T) {
	var output bytes.Buffer
	err := runMigrationProcess(t.Context(), migrationEnvironment(t,
		"EVYDENCE_DATABASE_URL=postgres://evydence@127.0.0.1:1/evydence?sslmode=disable&connect_timeout=1",
		"EVYDENCE_MIGRATIONS_DIR="+filepath.Join(t.TempDir(), "PRIVATE_MISSING"),
		"EVYDENCE_MIGRATION_TARGET=a", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=PRIVATE_MISSING"), &output, applyMigrations)
	if !errors.Is(err, postgres.ErrMigrationPlan) || strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("command opened the database before validating its plan or leaked input", err)
	}
}

type migrationCommandFixture struct {
	ctx         context.Context
	admin       *pgx.Conn
	schema      string
	databaseURL string
	application string
	dir         string
	checksums   string
}

func newMigrationCommandFixture(t *testing.T, bodies map[string]string) *migrationCommandFixture {
	t.Helper()
	raw := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("evydence_migration_command_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	created := false
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if created {
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Error(err)
			}
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	created = true
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("migration command integration requires a PostgreSQL URI", err)
	}
	query := parsed.Query()
	query.Set("search_path", quoted)
	query.Set("application_name", schema)
	parsed.RawQuery = query.Encode()
	f := &migrationCommandFixture{ctx: ctx, admin: admin, schema: schema, databaseURL: parsed.String(), application: schema,
		dir: t.TempDir(), checksums: filepath.Join(t.TempDir(), "migrations.sha256")}
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		body := []byte(bodies[name])
		if err := os.WriteFile(filepath.Join(f.dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  migrations/%s\n", sha256.Sum256(body), name)
	}
	if err := os.WriteFile(f.checksums, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *migrationCommandFixture) environment(t *testing.T, target, seconds string, extra ...string) config.Environment {
	t.Helper()
	entries := []string{"ENV=production", "EVYDENCE_DATABASE_URL=" + f.databaseURL,
		"EVYDENCE_MIGRATIONS_DIR=" + f.dir, "EVYDENCE_MIGRATION_TARGET=" + target,
		"EVYDENCE_MIGRATION_CHECKSUMS_FILE=" + f.checksums, "EVYDENCE_MIGRATION_TIMEOUT_SECONDS=" + seconds}
	return migrationEnvironment(t, append(entries, extra...)...)
}

func (f *migrationCommandFixture) requireClosedConnections(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	for {
		var count int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1`, f.application).Scan(&count); err != nil {
			t.Fatal("inspect migration command connection cleanup", err)
		}
		if count == 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("migration command retained an owned database connection")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestMigrationCommandAppliesVerifiedTarget(t *testing.T) {
	f := newMigrationCommandFixture(t, map[string]string{
		"a.up.sql": "CREATE TABLE command_effects(value integer NOT NULL); INSERT INTO command_effects(value)VALUES(1);",
		"b.up.sql": "INSERT INTO command_effects(value)VALUES(2);",
		"c.up.sql": "INSERT INTO command_effects(value)VALUES(99);"})
	var output bytes.Buffer
	if err := runMigrationProcess(f.ctx, f.environment(t, "b", "30"), &output, applyMigrations); err != nil {
		t.Fatal("verified migration command failed", err)
	}
	var total, versions int
	quoted := pgx.Identifier{f.schema}.Sanitize()
	if err := f.admin.QueryRow(f.ctx, "SELECT (SELECT sum(value) FROM "+quoted+".command_effects),(SELECT count(*) FROM "+quoted+".schema_migrations)").Scan(&total, &versions); err != nil || total != 3 || versions != 2 {
		t.Fatal("command did not stop at its explicit verified target", total, versions, err)
	}
	f.requireClosedConnections(t)
}

func TestMigrationCommandExcludesActiveRuntimeLeases(t *testing.T) {
	for _, kind := range []string{"api", "worker"} {
		t.Run(kind, func(t *testing.T) {
			f := newMigrationCommandFixture(t, map[string]string{"a.up.sql": "CREATE TABLE command_effects(value integer NOT NULL);"})
			store, err := postgres.Open(f.ctx, f.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			acquire := store.AcquireRuntimeMigrationLease
			if kind == "api" {
				acquire = store.AcquireAPIWriterLease
			}
			release, err := acquire(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
				defer cancel()
				if err := release(cleanup); err != nil {
					t.Error(err)
				}
			}()
			var output bytes.Buffer
			err = runMigrationProcess(f.ctx, f.environment(t, "a", "1"), &output, applyMigrations)
			if err == nil || (kind == "api" && !strings.Contains(err.Error(), "already active")) ||
				(kind == "worker" && !errors.Is(err, context.DeadlineExceeded)) || strings.Contains(output.String(), "PRIVATE") {
				t.Fatal("native migration command overlapped an active runtime or lost its bounded result", err)
			}
			var created bool
			if err := f.admin.QueryRow(f.ctx, `SELECT to_regclass($1) IS NOT NULL`, pgx.Identifier{f.schema, "schema_migrations"}.Sanitize()).Scan(&created); err != nil || created {
				t.Fatal("excluded migration command changed tracking metadata", err)
			}
			cleanup, cancel := context.WithTimeout(f.ctx, time.Second)
			defer cancel()
			if err := release(cleanup); err != nil {
				t.Fatal(err)
			}
			store.Close()
			if err := runMigrationProcess(f.ctx, f.environment(t, "a", "1"), &output, applyMigrations); err != nil {
				t.Fatal("stopped runtime retained migration ownership", err)
			}
			f.requireClosedConnections(t)
		})
	}
}

func TestMigrationCommandEnforcesConfiguredBudget(t *testing.T) {
	f := newMigrationCommandFixture(t, map[string]string{"a.up.sql": "SELECT pg_sleep(2);"})
	var output bytes.Buffer
	err := runMigrationProcess(f.ctx, f.environment(t, "a", "1"), &output, applyMigrations)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("migration command ignored the configured one-second budget", err)
	}
	table := pgx.Identifier{f.schema, "schema_migrations"}.Sanitize()
	var exists bool
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		var versions int
		if err := f.admin.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&versions); err != nil || versions != 0 {
			t.Fatal("timed-out command committed a migration version", versions, err)
		}
	}
	f.requireClosedConnections(t)
}

func TestMigrationCommandRequiresExplicitLegacyAcknowledgement(t *testing.T) {
	f := newMigrationCommandFixture(t, map[string]string{"a.up.sql": "SELECT 1/0;", "b.up.sql": "INSERT INTO command_effects(value)VALUES(2);"})
	quoted := pgx.Identifier{f.schema}.Sanitize()
	if _, err := f.admin.Exec(f.ctx, "CREATE TABLE "+quoted+`.schema_migrations(version text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now());
 INSERT INTO `+quoted+`.schema_migrations(version,applied_at)VALUES('a','2001-01-01T00:00:00Z');
 CREATE TABLE `+quoted+`.command_effects(value integer NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := runMigrationProcess(f.ctx, f.environment(t, "b", "30"), &output, applyMigrations)
	if !errors.Is(err, postgres.ErrMigrationLegacyHistory) {
		t.Fatal("verified command did not reject unknown historical SQL by default", err)
	}
	legacyOutput := output.String()
	f.requireClosedConnections(t)
	output.Reset()
	if err := runMigrationProcess(f.ctx, f.environment(t, "b", "30", "EVYDENCE_MIGRATION_ALLOW_LEGACY_HISTORY=true"), &output, applyMigrations); err != nil {
		t.Fatal("explicit legacy acknowledgement did not permit the pending suffix", err)
	}
	var unknown, recorded bool
	if err := f.admin.QueryRow(f.ctx, "SELECT checksum_sha256 IS NULL AND applied_by IS NULL AND applied_at='2001-01-01T00:00:00Z'::timestamptz FROM "+quoted+".schema_migrations WHERE version='a'").Scan(&unknown); err != nil || !unknown {
		t.Fatal("legacy command fabricated provenance or rewrote the old row", err)
	}
	if err := f.admin.QueryRow(f.ctx, "SELECT checksum_sha256 IS NOT NULL AND applied_by=session_user FROM "+quoted+".schema_migrations WHERE version='b'").Scan(&recorded); err != nil || !recorded {
		t.Fatal("pending execution did not record actual checksum/principal", err)
	}
	f.requireClosedConnections(t)
	if !strings.Contains(legacyOutput, `"msg":"migration_legacy_history_required"`) || strings.Contains(legacyOutput, "PRIVATE") {
		t.Fatal("legacy rejection did not provide a fixed safe diagnostic")
	}
}

func TestMigrationCommandReportsStoredChecksumMismatchWithoutSQL(t *testing.T) {
	const first = "CREATE TABLE command_effects(value integer NOT NULL); INSERT INTO command_effects(value)VALUES(1);"
	const pending = "INSERT INTO command_effects(value)VALUES(99);"
	f := newMigrationCommandFixture(t, map[string]string{"a.up.sql": first, "b.up.sql": pending})
	var output bytes.Buffer
	if err := runMigrationProcess(f.ctx, f.environment(t, "a", "30"), &output, applyMigrations); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	const changed = "SELECT 'PRIVATE_CHANGED_SQL';"
	if err := root.WriteFile("a.up.sql", []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.OpenRoot(filepath.Dir(f.checksums))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	manifest := fmt.Sprintf("%x  migrations/a.up.sql\n%x  migrations/b.up.sql\n", sha256.Sum256([]byte(changed)), sha256.Sum256([]byte(pending)))
	if err := parent.WriteFile(filepath.Base(f.checksums), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = runMigrationProcess(f.ctx, f.environment(t, "b", "30", "EVYDENCE_MIGRATION_ALLOW_LEGACY_HISTORY=true"), &output, applyMigrations)
	if !errors.Is(err, postgres.ErrMigrationChecksum) || !strings.Contains(output.String(), `"msg":"migration_checksum_mismatch"`) || strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("stored mismatch was bypassed or not safely diagnosed", err)
	}
	var total, versions int
	quoted := pgx.Identifier{f.schema}.Sanitize()
	if err := f.admin.QueryRow(f.ctx, "SELECT (SELECT sum(value) FROM "+quoted+".command_effects),(SELECT count(*) FROM "+quoted+".schema_migrations)").Scan(&total, &versions); err != nil || total != 1 || versions != 1 {
		t.Fatal("stored mismatch reached pending SQL", total, versions, err)
	}
	f.requireClosedConnections(t)
}
