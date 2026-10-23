package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestWorkerProbePostgresRuntimeRecoversFromObjectOutageAndStops(t *testing.T) {
	t.Setenv("EVYDENCE_CHANGELOG_PULL_REQUEST", "30")

	// Keep this regression independent of which live-service settings happen
	// to be present in the outer harness. They are not production options.
	t.Setenv("EVYDENCE_TEST_S3_ENDPOINT", "PRIVATE_UNUSED_S3_ENDPOINT")
	t.Setenv("EVYDENCE_TEST_S3_ACCESS_KEY_ID", "PRIVATE_UNUSED_S3_ID")
	t.Setenv("EVYDENCE_TEST_S3_SECRET_ACCESS_KEY", "PRIVATE_UNUSED_S3_SECRET")
	t.Setenv("EVYDENCE_TEST_S3_USE_SSL", "false")
	for _, enabled := range []bool{false, true} {
		name := "metrics-disabled"
		if enabled {
			name = "metrics-enabled"
		}
		t.Run(name, func(t *testing.T) { workerProbePostgresRuntime(t, enabled) })
	}
}

func workerProbePostgresRuntime(t *testing.T, metricsEnabled bool) {
	t.Helper()
	base := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	// This fixture supplies its own runtime settings. Preserve the database URL
	// locally, isolate developer/CI project inputs, and restore them at cleanup.
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "EVYDENCE_") {
			t.Setenv(name, value)
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}

	admin, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.WithoutCancel(t.Context()))
	schema := "evydence_worker_probes_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(t.TempDir(), "private-object-root")
	metricsAddress, metricsFile := "", ""
	if metricsEnabled {
		reserved, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		metricsAddress = reserved.Addr().String()
		if err := reserved.Close(); err != nil {
			t.Fatal(err)
		}
		metricsFile = workerMetricsTokenFixture(t)
	}
	for name, value := range map[string]string{
		"ENV": "production", "EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": postgresURLWithSearchPath(t, base, schema),
		"EVYDENCE_MIGRATIONS_DIR": "../../migrations", "EVYDENCE_SKIP_MIGRATIONS": "false", "EVYDENCE_POSTGRES_LOAD_MODE": "relational_only",
		"EVYDENCE_OBJECT_STORE": "filesystem", "EVYDENCE_OBJECT_DIR": objects, "EVYDENCE_WORKER_HEALTH_ADDR": address,
		"EVYDENCE_CONFIGURATION_REVISION": "", "EVYDENCE_CONFIGURATION_REVISION_FILE": "",
		"EVYDENCE_WORKER_POLL_INTERVAL": "10ms", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS": "1", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS": "2",
		"EVYDENCE_WORKER_METRICS_ADDR": metricsAddress, "EVYDENCE_WORKER_METRICS_TOKEN_FILE": metricsFile,
	} {
		t.Setenv(name, value)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runWorkerWithContext(ctx, nil) }()
	joined := false
	defer func() {
		stop()
		if !joined {
			if err := workerProbeAwait(t, done); err != nil {
				t.Error("worker did not stop cleanly", err)
			}
		}
	}()
	waitReady := func(want bool) {
		t.Helper()
		deadline, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case err := <-done:
				joined = true
				t.Fatal("worker exited before probe expectation", err)
			default:
			}
			if (runWorkerHealthcheck(deadline, nil) == nil) == want {
				return
			}
			select {
			case <-tick.C:
			case <-deadline.Done():
				t.Fatal("worker readiness did not reach expected state", want)
			}
		}
	}
	waitReady(true)
	metricsClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer metricsClient.CloseIdleConnections()
	if metricsEnabled {
		body, err := workerMetricsRequest(t, metricsClient, metricsAddress)
		if err != nil || !strings.Contains(body, `evydence_queue_jobs{service="worker",state="queued"} 0`) || !strings.Contains(body, `evydence_db_pool_connections{pool="primary",service="worker"`) {
			t.Fatal("running worker did not expose its actual database/pool metrics", err)
		}
		r, err := http.NewRequestWithContext(t.Context(), "GET", "http://"+metricsAddress+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer evy_PRIVATE_TENANT_KEY")
		response, err := metricsClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatal("tenant key accessed native worker metrics", response.StatusCode)
		}
	}
	for _, mode := range []string{"--startup", "--liveness"} {
		if err := runWorkerHealthcheck(t.Context(), []string{mode}); err != nil {
			t.Fatal("initialized worker probe failed", err)
		}
	}
	if err := os.Rename(objects, objects+"-preserved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objects, []byte("private-unavailable-object-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitReady(false)
	for _, mode := range []string{"--startup", "--liveness"} {
		if err := runWorkerHealthcheck(t.Context(), []string{mode}); err != nil {
			t.Fatal("object outage incorrectly blocked startup/liveness", err)
		}
	}
	if err := os.Remove(objects); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(objects+"-preserved", objects); err != nil {
		t.Fatal(err)
	}
	waitReady(true)
	stop()
	err = workerProbeAwait(t, done)
	joined = true
	if err != nil {
		t.Fatal("worker runtime shutdown failed", err)
	}
	if err := runWorkerHealthcheck(t.Context(), []string{"--liveness"}); err == nil {
		t.Fatal("closed worker listener reported liveness")
	}
	if metricsEnabled {
		if _, err := workerMetricsRequest(t, metricsClient, metricsAddress); err == nil {
			t.Fatal("worker metrics listener survived runtime shutdown")
		}
	}
}
