package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestWorkerMetricsInvalidConfigurationStopsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "host=PRIVATE_DATABASE")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", "")
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "127.0.0.1:9091")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", "/PRIVATE_MISSING_OPERATOR_TOKEN")
	err := runWorkerWithContext(t.Context(), nil)
	if !errors.Is(err, config.ErrSecretResolution) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("invalid metrics configuration reached runtime or exposed its input", err)
	}
}
