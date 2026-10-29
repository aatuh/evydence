package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrationRunnerFreezesSQLBeforeLockWait(t *testing.T) {
	for _, mutation := range []string{"overwrite", "remove", "add", "replace_directory"} {
		t.Run(mutation, func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			dir := filepath.Join(t.TempDir(), "migrations")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			first := filepath.Join(dir, "a.up.sql")
			second := filepath.Join(dir, "b.up.sql")
			for _, name := range []string{first, second} {
				if err := os.WriteFile(name, []byte("INSERT INTO migration_effects(value) VALUES(1);"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f.hold(migrationRunnerLockNamespace)
			result := f.start(f.ctx, dir)
			f.waitForDatabaseWaiter()
			var err error
			switch mutation {
			case "overwrite":
				err = os.WriteFile(second, []byte("INSERT INTO migration_effects(value) VALUES(99);"), 0o600)
			case "remove":
				err = os.Remove(second)
			case "add":
				err = os.WriteFile(filepath.Join(dir, "c.up.sql"), []byte("INSERT INTO migration_effects(value) VALUES(99);"), 0o600)
			case "replace_directory":
				if err = os.Rename(dir, dir+"-old"); err == nil {
					if err = os.Mkdir(dir, 0o700); err == nil {
						err = os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("INSERT INTO migration_effects(value) VALUES(99);"), 0o600)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			f.unlock()
			select {
			case outcome := <-result:
				if outcome.err != nil || outcome.count != 2 {
					t.Fatal("runner did not apply the frozen two-file catalog", outcome.count, outcome.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("runner did not finish after releasing catalog barrier")
			}
			f.requireCounts(2, 2)
			var total int
			if err := f.admin.QueryRow(f.ctx, "SELECT sum(value) FROM "+f.quoted+".migration_effects").Scan(&total); err != nil || total != 2 {
				t.Fatal("runner executed SQL edited after its database wait began", total, err)
			}
		})
	}
}

func TestMigrationRunnerRejectsOversizeCatalogBeforeSQL(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("INSERT INTO migration_effects(value) VALUES(1);"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A valid SQL comment beyond the per-file budget would otherwise be applied.
	body := "/*" + strings.Repeat(" ", (4<<20)-3) + "*/"
	if err := os.WriteFile(filepath.Join(dir, "z_PRIVATE.up.sql"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := f.stores[0].ApplyMigrations(f.ctx, dir)
	if err == nil || count != 0 {
		t.Fatal("oversized catalog was not rejected before applying its first SQL", count, err)
	}
	if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), dir) {
		t.Fatal("migration snapshot rejection disclosed operator-controlled paths")
	}
	f.requireCounts(0, 0)
}

func TestMigrationCatalogBoundsUpFileCount(t *testing.T) {
	dir := t.TempDir()
	for i := range 1025 {
		if i == 1024 {
			if names, err := migrationNames(dir); err != nil || len(names) != 1024 {
				t.Fatal("migration catalog rejected its supported file-count boundary", len(names), err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d.up.sql", i)), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := migrationNames(dir); err == nil || names != nil {
		t.Fatal("migration catalog returned excessive or partial names")
	}
}

func TestMigrationSnapshotPreservesExactOwnedBytes(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"b.up.sql": "\nSELECT 2;\n", "a.up.sql": "", "ignored.down.sql": "PRIVATE_IGNORED"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := loadMigrationCatalog(t.Context(), dir)
	if err != nil || len(catalog) != 2 || catalog[0].name != "a.up.sql" || catalog[0].body != "" || catalog[1].name != "b.up.sql" || catalog[1].body != "\nSELECT 2;\n" {
		t.Fatal("snapshot changed catalog selection, order or exact SQL bytes", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("SELECT 99;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if catalog[1].body != "\nSELECT 2;\n" {
		t.Fatal("snapshot did not own immutable SQL bytes")
	}
}

func TestMigrationSnapshotBoundsFileAndTotalBytes(t *testing.T) {
	for _, limit := range []string{"file", "total"} {
		t.Run(limit, func(t *testing.T) {
			dir := t.TempDir()
			count := 1
			if limit == "total" {
				count = 8
			}
			for i := range count {
				path := filepath.Join(dir, fmt.Sprintf("%02d.up.sql", i))
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(4 << 20)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			catalog, err := loadMigrationCatalog(t.Context(), dir)
			if err != nil || len(catalog) != count {
				t.Fatal("snapshot rejected its supported byte boundary", err)
			}
			for _, script := range catalog {
				if len(script.body) != 4<<20 {
					t.Fatal("snapshot truncated supported SQL bytes")
				}
			}
			if limit == "file" {
				if err := os.Truncate(filepath.Join(dir, "00.up.sql"), (4<<20)+1); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(dir, "z.up.sql"), []byte(" "), 0o600); err != nil {
				t.Fatal(err)
			}
			if catalog, err := loadMigrationCatalog(t.Context(), dir); !errors.Is(err, errMigrationCatalog) || catalog != nil {
				t.Fatal("snapshot admitted excess bytes or returned a partial catalog", err)
			}
		})
	}
}

func TestMigrationCatalogBoundsIgnoredDirectoryEntries(t *testing.T) {
	dir := t.TempDir()
	for i := range 8193 {
		if i == 8192 {
			if names, err := migrationNames(dir); err != nil || len(names) != 0 {
				t.Fatal("migration catalog rejected its supported directory-entry boundary", err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d.ignored", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := migrationNames(dir); !errors.Is(err, errMigrationCatalog) || names != nil {
		t.Fatal("migration catalog did not bound ignored directory entries", err)
	}
}

func TestMigrationSnapshotCancellationPrecedesFilesystemAndDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	missing := filepath.Join(t.TempDir(), "PRIVATE_MISSING")
	if catalog, err := loadMigrationCatalog(ctx, missing); !errors.Is(err, context.Canceled) || catalog != nil {
		t.Fatal("snapshot did filesystem work or lost cancellation", err)
	}
	if names, err := migrationNamesContext(ctx, missing); !errors.Is(err, context.Canceled) || names != nil {
		t.Fatal("catalog did filesystem work or lost cancellation", err)
	}
	var store *Store
	if applied, err := store.ApplyMigrations(ctx, missing); !errors.Is(err, context.Canceled) || applied != 0 {
		t.Fatal("canceled snapshot reached database work", applied, err)
	}
}
