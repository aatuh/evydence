package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestWorkerProbePostgresRuntimeRecoversFromObjectOutageAndStops(t *testing.T) {
	base := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
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
	for name, value := range map[string]string{
		"ENV": "production", "EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": postgresURLWithSearchPath(t, base, schema),
		"EVYDENCE_MIGRATIONS_DIR": "../../migrations", "EVYDENCE_SKIP_MIGRATIONS": "false", "EVYDENCE_POSTGRES_LOAD_MODE": "relational_only",
		"EVYDENCE_OBJECT_STORE": "filesystem", "EVYDENCE_OBJECT_DIR": objects, "EVYDENCE_WORKER_HEALTH_ADDR": address,
		"EVYDENCE_CONFIGURATION_REVISION": "", "EVYDENCE_CONFIGURATION_REVISION_FILE": "",
		"EVYDENCE_WORKER_POLL_INTERVAL": "10ms", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS": "1", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS": "2",
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
}
