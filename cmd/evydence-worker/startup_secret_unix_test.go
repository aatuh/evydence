//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestWorkerProcessResolvesDSNAndMetricsFilesBeforeStartup(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "PRIVATE_DATABASE")
	if err := os.WriteFile(database, []byte("host=PRIVATE_DB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tokenFile := workerMetricsTokenFixture(t)
	e := workerCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=", "EVYDENCE_DATABASE_URL_FILE="+database, "EVYDENCE_WORKER_METRICS_TOKEN_FILE="+tokenFile)
	var output bytes.Buffer
	called := false
	err := runWorkerProcess(t.Context(), e, &output, func(_ context.Context, settings config.Configuration) error {
		called = true
		metrics, err := workerMetricsConfigFromSettings(settings)
		want := sha256.Sum256([]byte("evymetrics_" + strings.Repeat("a", 64)))
		if err != nil || settings.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DB" || !metrics.enabled || metrics.address.String() != "127.0.0.1:9091" || metrics.tokenHash != want || strings.Contains(fmt.Sprintf("%v", metrics), "PRIVATE") {
			t.Fatal("startup did not receive the resolved DSN and hash-only metrics credential", err)
		}
		return nil
	})
	if err != nil || !called || strings.Contains(output.String(), "PRIVATE") || strings.Contains(output.String(), "evymetrics_") {
		t.Fatal("secret-file startup failed or disclosed source data", err)
	}
}

func TestWorkerProcessRejectsPrivateFileConflictsAndPermissions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "PRIVATE_DSN")
	if err := os.WriteFile(file, []byte("host=PRIVATE_DB"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inline string
		want   error
	}{{"", config.ErrSecretResolution}, {"host=PRIVATE_INLINE", config.ErrConflictingSecretSources}} {
		var output bytes.Buffer
		called := false
		err := runWorkerProcess(t.Context(), workerCapturedEnvironment(t, "EVYDENCE_DATABASE_URL="+tc.inline, "EVYDENCE_DATABASE_URL_FILE="+file), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if !errors.Is(err, tc.want) || called || strings.Contains(output.String()+err.Error(), "PRIVATE") || strings.Contains(output.String(), `"result_code":"started"`) {
			t.Fatal("file failure reached worker startup or exposed source input", err)
		}
	}
}

func TestWorkerMetricsSettingsRequireExplicitCredentialResolution(t *testing.T) {
	settings, err := config.Parse(workerCapturedEnvironment(t, "EVYDENCE_WORKER_METRICS_TOKEN_FILE="+workerMetricsTokenFixture(t)), config.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workerMetricsConfigFromSettings(settings); !errors.Is(err, errWorkerMetricsConfig) {
		t.Fatal("unresolved metrics input enabled a listener", err)
	}
}
