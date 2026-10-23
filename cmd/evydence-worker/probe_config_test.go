package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestWorkerProbeUsesCapturedConfiguration(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/startup" {
			t.Error("probe mode changed")
		}
		_, _ = w.Write([]byte(`{"data":{"status":"ok"},"meta":{"process":"worker"}}`))
	}))
	defer server.Close()
	e, err := config.Capture([]string{"EVYDENCE_WORKER_HEALTH_ADDR=" + server.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", "0.0.0.0:1")
	t.Setenv("EVYDENCE_LOG_LEVEL", "PRIVATE_INVALID")
	var output bytes.Buffer
	err = runWorkerRoleProcess(t.Context(), e, config.WorkerProbe, &output, func(ctx context.Context, settings config.Configuration) error {
		return runWorkerHealthcheckConfigured(ctx, []string{"--startup"}, settings.Worker().HealthAddress)
	})
	if err != nil || calls.Load() != 1 || strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"succeeded"`) {
		t.Fatal("probe used ambient settings or lost safe lifecycle logging", err)
	}
}

func TestWorkerProbePreflightRejectsBeforeContactingWorker(t *testing.T) {
	e, err := config.Capture([]string{"EVYDENCE_LOG_FORMAT=PRIVATE_INVALID"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	called := false
	err = runWorkerRoleProcess(t.Context(), e, config.WorkerProbe, &output, func(context.Context, config.Configuration) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, config.ErrInvalidValue) || strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"rejected"`) {
		t.Fatal("invalid probe settings reached network startup or leaked input", err)
	}
}

func TestWorkerProbeCommandIgnoresUnusedDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"status":"ok"},"meta":{"process":"worker"}}`))
	}))
	defer server.Close()
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", server.Listener.Addr().String())
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_INVALID_DSN")
	t.Setenv("EVYDENCE_DATABASE_URL_FILE", "PRIVATE_INVALID_FILE")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", "/PRIVATE_MISSING/token")
	t.Setenv("EVYDENCE_WORKER_BATCH_SIZE", "0")
	for _, name := range []string{"healthcheck", "--healthcheck"} {
		if err := runWithArgs([]string{name}); err != nil {
			t.Fatal("probe command acquired an unused runtime dependency", err)
		}
	}
}
