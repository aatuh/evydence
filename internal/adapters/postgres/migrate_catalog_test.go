package postgres

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMigrationCatalogRejectsNonRegularUpFiles(t *testing.T) {
	for _, tc := range []struct{ name, kind, file string }{
		{"symlink_first", "symlink", "PRIVATE.up.sql"},
		{"symlink_after_valid", "symlink", "z_PRIVATE.up.sql"},
		{"directory_first", "directory", "PRIVATE.up.sql"},
		{"directory_after_valid", "directory", "z_PRIVATE.up.sql"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
				t.Fatal(err)
			}
			invalid := filepath.Join(dir, tc.file)
			if tc.kind == "symlink" {
				outside := filepath.Join(t.TempDir(), "outside.sql")
				if err := os.WriteFile(outside, []byte("SELECT 2;"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, invalid); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(invalid, 0o700); err != nil {
				t.Fatal(err)
			}
			names, err := migrationNames(dir)
			if err == nil || len(names) != 0 {
				t.Fatal("migration catalog admitted a non-regular up file or returned partial results")
			}
			if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), dir) {
				t.Fatal("migration catalog rejection disclosed operator-controlled paths")
			}
		})
	}
}

func TestMigrationCatalogNamesPreserveOrderingAndIgnoreOtherEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.up.sql", "a.up.sql", "a.down.sql", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "unrelated"), 0o700); err != nil {
		t.Fatal(err)
	}
	names, err := migrationNames(dir)
	if err != nil || !reflect.DeepEqual(names, []string{"a.up.sql", "b.up.sql"}) {
		t.Fatal("migration catalog changed supported regular-file ordering or ignored entries", names, err)
	}
}
