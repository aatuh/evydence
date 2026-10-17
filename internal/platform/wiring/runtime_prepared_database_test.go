package wiring

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestRuntimeRejectsMismatchedPreparedDatabaseBeforeResources(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	prepared, err := postgres.PreparePoolConfig(t.Context(), "host=127.0.0.1 port=1 sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "PRIVATE_OBJECTS")
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{
		Process: Worker, Profile: PostgreSQL, DatabaseURL: "host=127.0.0.1 port=2 sslmode=disable",
		DatabaseConfiguration: prepared, LoadMode: "relational_only",
		ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: directory},
	})
	if runtime != nil || !errors.Is(err, postgres.ErrInvalidConfiguration) {
		t.Fatal("mismatched prepared settings reached runtime startup", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid database configuration created object storage")
	}
}
