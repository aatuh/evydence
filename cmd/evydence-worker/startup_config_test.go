package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
)

func workerCapturedEnvironment(t *testing.T, extra ...string) config.Environment {
	t.Helper()
	values := map[string]string{"EVYDENCE_RUNTIME_PROFILE": "postgres", "EVYDENCE_DATABASE_URL": "host=PRIVATE_DB"}
	for _, entry := range extra {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	e, err := config.Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestWorkerProcessUsesCapturedTypedSettings(t *testing.T) {
	e := workerCapturedEnvironment(t, "EVYDENCE_WORKER_POLL_INTERVAL=250ms", "EVYDENCE_WORKER_BATCH_SIZE=2", "EVYDENCE_WORKER_MAX_PAYLOAD_BYTES=1234", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS=3", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=4", "EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_S3_ENDPOINT=storage.internal:9000", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_ACCESS_KEY_ID= PRIVATE_ID ", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_KEY")
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED")
	t.Setenv("EVYDENCE_LOG_FORMAT", "PRIVATE_INVALID")
	t.Setenv("EVYDENCE_S3_SECRET_ACCESS_KEY", "PRIVATE_CHANGED")
	var output bytes.Buffer
	want := errors.New("PRIVATE_RUNTIME_FAILURE")
	called := false
	err := runWorkerProcess(t.Context(), e, &output, func(ctx context.Context, settings config.Configuration) error {
		called = true
		w, runtime := settings.Worker(), workerRuntimeConfigFromSettings(settings)
		if settings.Role() != config.Worker || logging.FromContext(ctx) == nil || w.PollInterval != 250*time.Millisecond || w.BatchSize != 2 || w.MaxPayloadBytes != 1234 || w.ShutdownTimeout != 3*time.Second || runtime.CleanupTimeout != 4*time.Second || runtime.DatabaseURL != "host=PRIVATE_DB" || runtime.ObjectStore.AccessKeyID != " PRIVATE_ID " || runtime.ObjectStore.SecretAccessKey != "PRIVATE_KEY" || runtime.ObjectStore.Endpoint != "storage.internal:9000" {
			t.Fatal("worker startup used ambient input or lost typed settings")
		}
		return want
	})
	if !called || !errors.Is(err, want) || strings.Contains(output.String(), "PRIVATE") || strings.Count(output.String(), "\n") != 2 || !strings.Contains(output.String(), `"result_code":"failed"`) {
		t.Fatal("worker lifecycle changed its result or exposed details")
	}
}

func TestWorkerProcessRejectsInvalidInputBeforeStartup(t *testing.T) {
	for _, tc := range []struct {
		extra []string
		want  error
	}{
		{[]string{"EVYDENCE_DATABASE_URL="}, config.ErrMissingValue},
		{[]string{"EVYDENCE_RUNTIME_PROFILE=local_memory"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_WORKER_POLL_INTERVAL=PRIVATE_BAD"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_WORKER_BATCH_SIZE=0"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS=301"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=61"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_WORKER_MAX_PAYLOAD_BYTES=9223372036854775807"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_MISSING"}, config.ErrSecretResolution},
		{[]string{"ENV=production", "EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, config.ErrUnknownOption},
		{[]string{"EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_S3_ENDPOINT=https://PRIVATE_INVALID", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_ACCESS_KEY_ID=PRIVATE_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_KEY"}, config.ErrInvalidValue},
	} {
		var output bytes.Buffer
		called := false
		err := runWorkerProcess(t.Context(), workerCapturedEnvironment(t, tc.extra...), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if !errors.Is(err, tc.want) || called || strings.Contains(output.String()+err.Error(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"rejected"`) || strings.Contains(output.String(), `"result_code":"started"`) {
			t.Fatal("invalid input reached worker startup or leaked configuration", err)
		}
	}
}

func TestWorkerProcessRejectsCancellationBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	called := false
	err := runWorkerProcess(ctx, workerCapturedEnvironment(t), &output, func(context.Context, config.Configuration) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called || strings.Contains(output.String(), `"result_code":"started"`) {
		t.Fatal("cancelled worker entered startup", err)
	}
}
