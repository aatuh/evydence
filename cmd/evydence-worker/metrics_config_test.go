package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func workerMetricsConfigFixture(t *testing.T) (workerMetricsConfig, error) {
	t.Helper()
	var entries []string
	for _, name := range []string{"EVYDENCE_WORKER_METRICS_ADDR", "EVYDENCE_WORKER_METRICS_TOKEN_FILE"} {
		if value, present := os.LookupEnv(name); present {
			entries = append(entries, name+"="+value)
		}
	}
	input, err := config.Prepare(workerCapturedEnvironment(t, entries...), config.Worker)
	if err != nil {
		return workerMetricsConfig{}, err
	}
	settings, err := config.Resolve(context.Background(), input, true)
	if err != nil {
		return workerMetricsConfig{}, err
	}
	return workerMetricsConfigFromSettings(settings)
}

func workerMetricsTokenFixture(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "PRIVATE_METRICS_TOKEN")
	if err := os.WriteFile(file, []byte("evymetrics_"+strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestWorkerMetricsConfigurationIsOptionalAndRequiresPrivateCredential(t *testing.T) {
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", "")
	cfg, err := workerMetricsConfigFixture(t)
	if err != nil || cfg.enabled {
		t.Fatal("disabled worker metrics require configuration", err)
	}
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", workerMetricsTokenFixture(t))
	cfg, err = workerMetricsConfigFixture(t)
	if err != nil || !cfg.enabled || cfg.address.String() != "127.0.0.1:9091" {
		t.Fatal("protected worker metrics defaults rejected", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), "evymetrics_") || strings.Contains(fmt.Sprintf("%+v", cfg), "PRIVATE") {
		t.Fatal("worker metrics configuration retains raw secret/path")
	}
	for _, address := range []string{"10.1.2.3:9091", "[fd00::1]:9091", "[::1]:9091"} {
		t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", address)
		if _, err := workerMetricsConfigFixture(t); err != nil {
			t.Fatal("literal private monitoring bind rejected", address, err)
		}
	}
}

func TestWorkerMetricsConfigurationRejectsUnsafeInputsWithoutEcho(t *testing.T) {
	for _, address := range []string{"PRIVATE_HOST:9091", "0.0.0.0:9091", "[::]:9091", "8.8.8.8:9091", "127.0.0.1:0", "127.0.0.1:99999", "http://127.0.0.1:9091", strings.Repeat("PRIVATE", 1000)} {
		t.Run("invalid-bind", func(t *testing.T) {
			t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", address)
			t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", workerMetricsTokenFixture(t))
			if _, err := workerMetricsConfigFixture(t); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe bind accepted or echoed", err)
			}
		})
	}
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "127.0.0.1:9091")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", "")
	if _, err := workerMetricsConfigFixture(t); err == nil {
		t.Fatal("worker metrics listener enabled without credential")
	}
	for _, contents := range []string{"", "PRIVATE_BAD_TOKEN", "evysso_" + strings.Repeat("a", 64), "evymetrics_" + strings.Repeat("A", 64), "evymetrics_" + strings.Repeat("a", 64) + "\n\n", strings.Repeat("PRIVATE", 1000)} {
		file := workerMetricsTokenFixture(t)
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", file)
		if _, err := workerMetricsConfigFixture(t); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe credential accepted or echoed", err)
		}
	}
	for _, mode := range []os.FileMode{0644, 0660} {
		file := workerMetricsTokenFixture(t)
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", file)
		if _, err := workerMetricsConfigFixture(t); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe secret file permissions accepted or echoed", err)
		}
	}
	for _, file := range []string{"PRIVATE_RELATIVE_TOKEN", "/PRIVATE_MISSING_TOKEN", t.TempDir(), strings.Repeat("PRIVATE", 1000)} {
		t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", file)
		if _, err := workerMetricsConfigFixture(t); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe credential path accepted or echoed", err)
		}
	}
}

func TestWorkerMetricsSecretProjectionSymlinksStayInsideParent(t *testing.T) {
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "")
	root := t.TempDir()
	dir := filepath.Join(root, "..2026")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("evymetrics_"+strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "token"), 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026", filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "token")
	if err := os.Symlink("..data/token", link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", link)
	if _, err := workerMetricsConfigFixture(t); err != nil {
		t.Fatal("private projected secret rejected", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(workerMetricsTokenFixture(t), link); err != nil {
		t.Fatal(err)
	}
	if _, err := workerMetricsConfigFixture(t); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("escaping secret projection accepted or echoed", err)
	}
}
