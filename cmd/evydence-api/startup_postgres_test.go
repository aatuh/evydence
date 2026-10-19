package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/config"
)

type apiStartupSigner struct{ constructions, checks, signs, closes atomic.Int32 }

func (s *apiStartupSigner) Sign(context.Context, app.SigningRequest) (app.SigningResult, error) {
	s.signs.Add(1)
	return app.SigningResult{}, app.ErrDependencyUnavailable
}
func (s *apiStartupSigner) CheckReadiness(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.checks.Add(1)
	return nil
}
func (s *apiStartupSigner) Close() error { s.closes.Add(1); return nil }

// Native provider ports are fakes; real PostgreSQL, migrations, bootstrap,
// listeners, readiness and cleanup use the production startup path.
func TestAPIProductionStartupUsesTypedConfigurationWithLivePostgres(t *testing.T) {
	base := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "EVYDENCE_TEST_") {
			t.Setenv(name, value)
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	admin, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatal("open live fixture")
	}
	defer admin.Close(context.WithoutCancel(t.Context()))
	schema := "evy_api_config_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("drop live API fixture")
		}
	}()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(t.TempDir(), "PRIVATE_OBJECTS")
	for name, value := range map[string]string{
		"ENV": "production", "EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": u.String(), "EVYDENCE_API_KEY_PEPPER": "PRIVATE_API_PEPPER_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"EVYDENCE_ADDR": address, "EVYDENCE_MIGRATIONS_DIR": "../../migrations", "EVYDENCE_OBJECT_STORE": "filesystem", "EVYDENCE_OBJECT_DIR": objects,
		"EVYDENCE_SIGNING_KEY_MODE": "external", "EVYDENCE_SIGNING_EXECUTOR_URL": "https://signer.example.test/sign", "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL": "https://signer.example.test/ready",
		"EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64": base64.StdEncoding.EncodeToString(make([]byte, 32)), "EVYDENCE_SIGNING_EXECUTOR_TOKEN": "PRIVATE_TOKEN",
		"EVYDENCE_WORKER_HEALTH_ADDR": "PRIVATE_INVALID_UNUSED", "EVYDENCE_WORKER_METRICS_TOKEN_FILE": "/PRIVATE_UNUSED_METRICS", "EVYDENCE_WORKER_BATCH_SIZE": "0",
	} {
		t.Setenv(name, value)
	}
	signer := &apiStartupSigner{}
	previous := newAPISigningExecutor
	t.Cleanup(func() { newAPISigningExecutor = previous })
	newAPISigningExecutor = func(ctx context.Context, p config.ProviderSettings) (app.SigningExecutor, error) {
		if ctx == nil || p.SigningKeyMode != "external" || p.SigningExecutorToken.Reveal() != "PRIVATE_TOKEN" {
			t.Error("signer lost typed settings")
		}
		signer.constructions.Add(1)
		return signer, nil
	}
	t.Run("configuration-before-providers", func(t *testing.T) {
		t.Setenv("EVYDENCE_HTTP_READ_TIMEOUT_SECONDS", "0")
		if err := runWithContext(t.Context()); !errors.Is(err, config.ErrInvalidValue) || signer.constructions.Load() != 0 {
			t.Fatal("invalid configuration constructed a provider", err)
		}
	})
	t.Run("native-before-providers", func(t *testing.T) {
		t.Setenv("PGSERVICE", "PRIVATE_MISSING")
		t.Setenv("PGSERVICEFILE", "/PRIVATE_MISSING/file")
		if err := runWithContext(t.Context()); !errors.Is(err, postgres.ErrInvalidConfiguration) || signer.constructions.Load() != 0 {
			t.Fatal("native resolution constructed a provider", err)
		}
	})
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx) }()
	joined := false
	defer func() {
		stop()
		if !joined {
			select {
			case err := <-done:
				if err != nil {
					t.Error("API startup fixture cleanup failed", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("API startup fixture did not join")
			}
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			joined = true
			t.Fatalf("production API stopped before readiness: %v", err)
		default:
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+"/v1/ready", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			_ = response.Body.Close()
			if readErr != nil || strings.Contains(string(body), "PRIVATE") {
				t.Fatal("readiness exposed input or could not be read")
			}
			ready = response.StatusCode == http.StatusOK
		}
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("production API did not become ready")
	}
	stop()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("production API shutdown failed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("production API shutdown did not join")
	}
	if signer.constructions.Load() != 1 || signer.checks.Load() < 1 || signer.signs.Load() != 0 || signer.closes.Load() != 1 {
		t.Fatal("provider ordering, readiness or ownership changed")
	}
	var tenants, keys int
	if err := admin.QueryRow(t.Context(), "SELECT count(*) FROM "+quoted+".tenants").Scan(&tenants); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(t.Context(), "SELECT count(*) FROM "+quoted+".api_keys").Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if tenants != 1 || keys != 1 {
		t.Fatal("durable native bootstrap was lost")
	}
}
