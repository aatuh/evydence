package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeMigrationPlanFixture(t *testing.T, bodies map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	checksums := filepath.Join(t.TempDir(), "PRIVATE_migrations.sha256")
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		body := []byte(bodies[name])
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  migrations/%s\n", sha256.Sum256(body), name)
	}
	if err := os.WriteFile(checksums, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, checksums
}

func migrationPlanFixtureBodies() map[string]string {
	return map[string]string{"a.up.sql": "SELECT 'PRIVATE_SQL';", "b.up.sql": "SELECT 2;\n", "c.up.sql": "SELECT 3;", "a.down.sql": "SELECT 4;"}
}

func TestMigrationPlanPreservesVerifiedOwnedTargetPrefix(t *testing.T) {
	for _, format := range []string{"text", "binary_crlf"} {
		t.Run(format, func(t *testing.T) {
			dir, checksums := writeMigrationPlanFixture(t, migrationPlanFixtureBodies())
			if format == "binary_crlf" {
				body, err := os.ReadFile(checksums)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.ReplaceAll(strings.ReplaceAll(string(body), "  migrations/", " *migrations/"), "\n", "\r\n"))
				parent, err := os.OpenRoot(filepath.Dir(checksums))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = parent.Close() }()
				if err := parent.WriteFile(filepath.Base(checksums), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := PrepareMigrationPlan(t.Context(), dir, "b", checksums)
			if err != nil || plan.TargetVersion() != "b" || len(plan.catalog) != 2 || plan.catalog[0].name != "a.up.sql" || plan.catalog[1].name != "b.up.sql" || plan.catalog[0].body != "SELECT 'PRIVATE_SQL';" {
				t.Fatal("verified plan changed the target prefix or SQL bytes", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("PRIVATE_CHANGED"), 0o600); err != nil {
				t.Fatal(err)
			}
			if plan.catalog[0].body != "SELECT 'PRIVATE_SQL';" {
				t.Fatal("verified plan did not own immutable SQL bytes")
			}
			data, err := json.Marshal(plan)
			if err != nil || strings.Contains(string(data)+fmt.Sprintf("%v %+v %#v", plan, plan, plan), "PRIVATE") {
				t.Fatal("default plan representations exposed migration SQL", err)
			}
		})
	}
}

func TestMigrationPlanRejectsInvalidInputsWithoutPartialPlan(t *testing.T) {
	for _, name := range []string{"empty_target", "unknown_target", "missing_manifest", "empty_manifest", "duplicate", "bad_hash", "bad_path", "missing_up", "unlisted_up", "unknown_up", "changed_up", "changed_after_target", "changed_down", "missing_down", "symlink_manifest", "record_limit", "byte_limit"} {
		t.Run(name, func(t *testing.T) {
			dir, checksums := writeMigrationPlanFixture(t, migrationPlanFixtureBodies())
			data, err := os.ReadFile(checksums)
			if err != nil {
				t.Fatal(err)
			}
			target := "b"
			write := func(path, body string) {
				t.Helper()
				parent, err := os.OpenRoot(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = parent.Close() }()
				if err := parent.WriteFile(filepath.Base(path), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "empty_target":
				target = ""
			case "unknown_target":
				target = "PRIVATE_UNKNOWN"
			case "missing_manifest":
				checksums += "_PRIVATE_MISSING"
			case "empty_manifest":
				data = nil
			case "duplicate":
				data = append(data, []byte(strings.Split(string(data), "\n")[0]+"\n")...)
			case "bad_hash":
				data[0] = 'G'
			case "bad_path":
				data = []byte(strings.ReplaceAll(string(data), "migrations/", "../PRIVATE/"))
			case "missing_up":
				data = []byte(strings.Join(strings.Split(string(data), "\n")[:2], "\n") + "\n")
			case "unlisted_up":
				write(filepath.Join(dir, "z.up.sql"), "SELECT 9;")
			case "unknown_up":
				data = append(data, []byte(fmt.Sprintf("%x  migrations/z.up.sql\n", sha256.Sum256([]byte("SELECT 9;"))))...)
			case "changed_up":
				write(filepath.Join(dir, "a.up.sql"), "PRIVATE_CHANGED")
			case "changed_after_target":
				write(filepath.Join(dir, "c.up.sql"), "PRIVATE_CHANGED")
			case "changed_down":
				write(filepath.Join(dir, "a.down.sql"), "PRIVATE_CHANGED")
			case "missing_down":
				if err := os.Remove(filepath.Join(dir, "a.down.sql")); err != nil {
					t.Fatal(err)
				}
			case "record_limit", "byte_limit":
				count := 253
				if name == "byte_limit" {
					count = 197
				}
				for i := range count {
					base := fmt.Sprintf("%03d", i)
					if name == "byte_limit" {
						base += "_" + strings.Repeat("x", 242)
					}
					base += ".down.sql"
					write(filepath.Join(dir, base), "SELECT 1;")
					data = append(data, []byte(fmt.Sprintf("%x  migrations/%s\n", sha256.Sum256([]byte("SELECT 1;")), base))...)
				}
			}
			if name != "missing_manifest" {
				write(checksums, string(data))
			}
			if name == "symlink_manifest" {
				if err := os.Rename(checksums, checksums+"_real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(checksums+"_real", checksums); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := PrepareMigrationPlan(t.Context(), dir, target, checksums)
			if !errors.Is(err, ErrMigrationPlan) || plan.catalog != nil || plan.TargetVersion() != "" {
				t.Fatal("invalid input produced a partial or accepted migration plan", err)
			}
			if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), dir) {
				t.Fatal("migration plan error disclosed operator-controlled inputs")
			}
		})
	}
}

func TestMigrationPlanPreservesCancellationAndRejectsZeroValue(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if plan, err := PrepareMigrationPlan(ctx, "PRIVATE_MISSING", "a", "PRIVATE_MISSING"); !errors.Is(err, context.Canceled) || plan.catalog != nil {
		t.Fatal("plan preparation lost cancellation", err)
	}
	var store *Store
	if applied, err := store.ApplyMigrationPlan(t.Context(), MigrationPlan{}); !errors.Is(err, ErrMigrationPlan) || applied != 0 {
		t.Fatal("zero-value plan reached database execution", applied, err)
	}
}

func TestMigrationPlanAcceptsCommittedReleaseChecksumFormat(t *testing.T) {
	const dir = "../../../migrations"
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	names, err := migrationNames(dir)
	if err != nil || len(names) == 0 {
		t.Fatal("committed migration catalog is unavailable", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for _, entry := range entries {
		body, err := root.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  migrations/%s\n", sha256.Sum256(body), entry.Name())
	}
	checksums := filepath.Join(t.TempDir(), "migrations.sha256")
	if err := os.WriteFile(checksums, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	target := strings.TrimSuffix(names[len(names)-1], ".up.sql")
	plan, err := PrepareMigrationPlan(t.Context(), dir, target, checksums)
	if err != nil || plan.TargetVersion() != target || len(plan.catalog) != len(names) {
		t.Fatal("command plan is incompatible with the committed release checksum format", err)
	}
}
