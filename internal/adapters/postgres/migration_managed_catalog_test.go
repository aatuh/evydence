package postgres

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the versioned audit DDL against the early native bootstrap, and
// adoption of an existing schema without rewriting any earlier execution rows.
func TestManagedMigrationSupportsCurrentCatalogFreshAndExisting(t *testing.T) {
	const dir = "../../../migrations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	var target string
	upCount := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%s  migrations/%s\n", migrationChecksum(string(body)), entry.Name())
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			upCount++
			target = strings.TrimSuffix(entry.Name(), ".up.sql")
		}
	}
	sums := filepath.Join(t.TempDir(), "migrations.sha256")
	if err := os.WriteFile(sums, []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareMigrationPlan(t.Context(), dir, target, sums)
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			expected := upCount
			if existing {
				if count, err := f.migrator.ApplyMigrations(f.ctx, dir); err != nil || count != upCount {
					t.Fatal("cannot prepare existing committed schema", count, err)
				}
				expected = 0
			}
			for _, want := range []int{expected, 0} {
				if count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); err != nil || count != want {
					t.Fatal("current catalog managed migration failed", count, err)
				}
				if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
					t.Fatal("current catalog did not admit its runtime", err)
				}
			}
			if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO tenants(id,name)VALUES('managed_current','Managed current catalog')"); err != nil {
				t.Fatal("current catalog grants omitted runtime persistence", err)
			}
			var events int
			if err := f.application.pool.QueryRow(f.ctx, "SELECT count(*) FROM schema_migration_operations").Scan(&events); err != nil || events != 4 {
				t.Fatal("current catalog lost initial or no-op operation audit", events, err)
			}
			for _, table := range []string{"schema_migrations", "schema_migration_operations"} {
				_, err := f.application.pool.Exec(f.ctx, "DELETE FROM "+table)
				requireRoleDenied(t, err)
			}
		})
	}
}
