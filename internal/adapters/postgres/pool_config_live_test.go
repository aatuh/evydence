package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedPoolConfigOpensFrozenNativeSettingsWithLivePostgres(t *testing.T) {
	base := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || u.Port() == "" {
		t.Fatal("live fixture requires an explicit host and port")
	}
	t.Setenv("PGHOST", u.Hostname())
	t.Setenv("PGPORT", u.Port())
	t.Setenv("PGSERVICE", "")
	query := u.Query()
	query.Set("sslmode", "disable")
	query.Set("passfile", filepath.Join(t.TempDir(), "PRIVATE_ABSENT_PASSFILE"))
	service := filepath.Join(t.TempDir(), "PRIVATE_SERVICE_FILE")
	if err := os.WriteFile(service, []byte("[PRIVATE_SERVICE]\napplication_name=PRIVATE_PREPARED\n"), 0600); err != nil {
		t.Fatal(err)
	}
	query.Set("service", "PRIVATE_SERVICE")
	query.Set("servicefile", service)
	u.Host, u.RawQuery = "", query.Encode()
	prepared, err := PreparePoolConfig(t.Context(), u.String())
	if err != nil {
		t.Fatal("native PostgreSQL preparation failed")
	}
	if err := os.WriteFile(service, []byte("PRIVATE_CORRUPTED"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGHOST", "PRIVATE_CHANGED_HOST")
	t.Setenv("PGPORT", "PRIVATE_INVALID")
	t.Setenv("PGSERVICE", "PRIVATE_CHANGED_SERVICE")
	for range 2 {
		store, err := OpenPrepared(t.Context(), prepared, StoreOptions{LoadMode: LoadModeRelationalOnly})
		if err != nil {
			t.Fatal("opening prepared settings reentered ambient resolution")
		}
		func() {
			defer store.Close()
			var application string
			if err := store.pool.QueryRow(t.Context(), "SELECT current_setting('application_name')").Scan(&application); err != nil || application != "PRIVATE_PREPARED" {
				t.Fatal("prepared open reloaded service settings")
			}
			for _, check := range []struct {
				reader bool
				want   string
			}{{false, "off"}, {true, "on"}} {
				pool := store.pool
				if check.reader {
					pool = store.packageReadPool
				}
				var state string
				if err := pool.QueryRow(t.Context(), "SELECT current_setting('transaction_read_only')").Scan(&state); err != nil || state != check.want {
					t.Fatal("prepared pool changed the writer/reader separation")
				}
			}
		}()
	}
	if _, mutated := prepared.config.ConnConfig.RuntimeParams["default_transaction_read_only"]; mutated {
		t.Fatal("opening a read pool mutated shared prepared settings")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if store, err := OpenPrepared(ctx, prepared, StoreOptions{}); store != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prepared open constructed a usable store")
	}
}
