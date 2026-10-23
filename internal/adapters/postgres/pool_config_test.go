package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparePoolConfigResolvesNativeServiceWithoutDialing(t *testing.T) {
	service := filepath.Join(t.TempDir(), "PRIVATE_SERVICE_FILE")
	text := "[PRIVATE_SERVICE]\nhost=PRIVATE_SERVICE_HOST\nport=5544\nuser=PRIVATE_USER\npassword=PRIVATE_PASSWORD\nsslmode=disable\n"
	if err := os.WriteFile(service, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGHOST", "PRIVATE_NATIVE_HOST")
	t.Setenv("PGSERVICE", "")
	prepared, err := PreparePoolConfig(t.Context(), "service=PRIVATE_SERVICE servicefile='"+service+"' port=5545")
	if err != nil || !prepared.IsPrepared() || prepared.config.ConnConfig.Host != "PRIVATE_SERVICE_HOST" || prepared.config.ConnConfig.Port != 5545 || prepared.config.ConnConfig.Password != "PRIVATE_PASSWORD" {
		t.Fatal("native/selected-service/explicit precedence was lost", err)
	}
	if err := os.WriteFile(service, []byte("PRIVATE_CORRUPTED"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICE", "PRIVATE_CHANGED")
	if prepared.config.ConnConfig.Host != "PRIVATE_SERVICE_HOST" || !prepared.Matches("service=PRIVATE_SERVICE servicefile='"+service+"' port=5545") || prepared.Matches("PRIVATE_OTHER") {
		t.Fatal("prepared configuration changed with its inputs")
	}
	encoded, err := json.Marshal(prepared)
	if err != nil || strings.Contains(string(encoded)+fmt.Sprintf("%v %#v %s", prepared, prepared, prepared), "PRIVATE") {
		t.Fatal("prepared PostgreSQL configuration disclosed credentials or references")
	}
}

func TestPreparePoolConfigRejectsUnsafeNativeResolutionWithoutCauses(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	service := filepath.Join(t.TempDir(), "PRIVATE_UNSAFE_SERVICE_FILE")
	if err := os.WriteFile(service, []byte("[PRIVATE_SERVICE]\nhost=PRIVATE_HOST\nsslmode=disable\npool_health_check_period=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{
		"service=PRIVATE_SERVICE servicefile='" + service + "'",
		"PRIVATE_INVALID_DSN",
		"service=PRIVATE_MISSING servicefile=/PRIVATE_MISSING/file",
		"host=PRIVATE_HOST sslmode=PRIVATE_INVALID password=PRIVATE_PASSWORD",
		"host=PRIVATE_HOST sslmode=disable port=0",
		"host=PRIVATE_HOST sslmode=disable pool_min_conns=-1",
		"host=PRIVATE_HOST sslmode=disable pool_min_idle_conns=-1",
		"host=PRIVATE_HOST sslmode=disable pool_max_conns=1 pool_min_conns=2",
		"host=PRIVATE_HOST sslmode=disable pool_max_conns=1 pool_min_idle_conns=2",
		"host=PRIVATE_HOST sslmode=disable pool_health_check_period=0",
		"host=PRIVATE_HOST sslmode=disable pool_max_conn_lifetime=-1s",
		"host=PRIVATE_HOST sslmode=disable pool_max_conn_idle_time=-1s",
		"host=PRIVATE_HOST sslmode=disable pool_max_conn_lifetime_jitter=-1s",
	} {
		prepared, err := PreparePoolConfig(t.Context(), dsn)
		if !errors.Is(err, ErrInvalidConfiguration) || errors.Unwrap(err) != nil || prepared.IsPrepared() || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid native resolution returned usable settings or exposed its cause", err)
		}
	}
}

func TestPreparePoolConfigChecksCancellationBeforeNativeFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{nil, ErrInvalidConfiguration}, {ctx, context.Canceled}} {
		prepared, err := PreparePoolConfig(tc.ctx, "service=PRIVATE_MISSING servicefile=/PRIVATE_MISSING/file")
		if !errors.Is(err, tc.want) || prepared.IsPrepared() {
			t.Fatal("invalid context reached native file resolution", err)
		}
	}
	if (PreparedPoolConfig{}).IsPrepared() || (PreparedPoolConfig{}).Matches("") {
		t.Fatal("zero prepared configuration is usable")
	}
	if store, err := OpenPrepared(t.Context(), PreparedPoolConfig{}, StoreOptions{}); !errors.Is(err, ErrInvalidConfiguration) || store != nil {
		t.Fatal("zero prepared configuration reached pool construction", err)
	}
}
