package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

func TestWorkerOperatorProcessUsesCapturedRuntimeSettings(t *testing.T) {
	for _, role := range []config.Role{config.WorkerReplay, config.WorkerReconcile} {
		e := workerCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_CAPTURED", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_MISSING/token", "EVYDENCE_WORKER_HEALTH_ADDR=PRIVATE_INVALID", "EVYDENCE_WORKER_BATCH_SIZE=0", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=3")
		t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED")
		t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
		called := false
		var output bytes.Buffer
		err := runWorkerRoleProcess(t.Context(), e, role, &output, func(_ context.Context, settings config.Configuration) error {
			called = true
			runtime := workerRuntimeConfigFromSettings(settings)
			if settings.Role() != role || runtime.DatabaseURL != "host=PRIVATE_CAPTURED" || runtime.Profile != wiring.PostgreSQL || runtime.CleanupTimeout != 3*time.Second || runtime.ObjectStore.Backend != "filesystem" {
				t.Fatal("operator used ambient or incomplete runtime settings")
			}
			return nil
		})
		if !called || err != nil || strings.Contains(output.String(), "PRIVATE") {
			t.Fatal("operator scope failed or leaked captured input", err)
		}
	}
}

func TestParserReplayConfiguredClosesIncompleteRuntimeWithTypedBudget(t *testing.T) {
	settings, err := config.Parse(workerCapturedEnvironment(t, "EVYDENCE_PARSER_REPLAY_TIMEOUT=4s", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=3"), config.WorkerReplay)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_PARSER_REPLAY_TIMEOUT", "PRIVATE_INVALID")
	t.Setenv("EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "PRIVATE_INVALID")
	want := errors.New("PRIVATE_CLEANUP_FAILURE")
	previous := openParserReplayRuntime
	t.Cleanup(func() { openParserReplayRuntime = previous })
	closed := 0
	openParserReplayRuntime = func(ctx context.Context, runtime wiring.RuntimeConfig) (parserReplayRuntime, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 4*time.Second || runtime.CleanupTimeout != 3*time.Second {
			t.Fatal("operator ignored typed operation or cleanup budget")
		}
		return parserReplayRuntime{close: func(closeCtx context.Context, budget time.Duration) error {
			closed++
			if closeCtx != ctx || budget != 3*time.Second {
				t.Fatal("replay cleanup lost its context or configured budget")
			}
			return want
		}}, nil
	}
	err = runParserReplayConfigured(t.Context(), settings, parserReplayArgs{TenantID: "ten_test", EvidenceID: "ev_test", ParserVersion: "v1", ActorID: "operator"})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "runtime is incomplete") || closed != 1 {
		t.Fatal("incomplete runtime lost failure or ownership cleanup", err)
	}
}
