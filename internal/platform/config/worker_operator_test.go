package config

import (
	"errors"
	"testing"
	"time"
)

func TestWorkerOperatorScopesValidateOnlyApplicableRuntimeSettings(t *testing.T) {
	for _, role := range []Role{WorkerReplay, WorkerReconcile} {
		e := roleEnvironment(t, Worker, true,
			"EVYDENCE_WORKER_HEALTH_ADDR=PRIVATE_INVALID", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_MISSING/token",
			"EVYDENCE_WORKER_BATCH_SIZE=0", "EVYDENCE_WORKER_POLL_INTERVAL=PRIVATE_INVALID",
			"EVYDENCE_CONFIGURATION_REVISION_FILE=PRIVATE_INVALID",
			"EVYDENCE_PARSER_REPLAY_TIMEOUT=3s", "EVYDENCE_RECONCILIATION_TIMEOUT=4s")
		input, err := Prepare(e, role)
		if err != nil {
			t.Fatal("operator evaluated daemon-only settings", err)
		}
		c, err := Resolve(t.Context(), input, true)
		if err != nil || c.Role() != role || c.Runtime().Profile != "postgres" || c.Runtime().PostgresLoadMode != "relational_only" || c.Runtime().ShutdownCleanupTimeout != 5*time.Second || c.Storage().Kind != "filesystem" || c.Worker().HealthAddress.IsValid() || c.Worker().MetricsAddress.IsValid() {
			t.Fatal("operator lost shared settings or loaded listener dependencies", err)
		}
		if role == WorkerReplay && (c.Worker().ParserReplayTimeout != 3*time.Second || c.Worker().ReconciliationTimeout != 0) || role == WorkerReconcile && (c.Worker().ReconciliationTimeout != 4*time.Second || c.Worker().ParserReplayTimeout != 0) {
			t.Fatal("operator timeout scopes are not independent")
		}
	}
}

func TestWorkerOperatorScopesRejectBeforeResourceResolution(t *testing.T) {
	for _, role := range []Role{WorkerReplay, WorkerReconcile} {
		for _, entry := range []string{
			"EVYDENCE_RUNTIME_PROFILE=local_memory", "EVYDENCE_DATABASE_URL=PRIVATE_INVALID",
			"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=0", "PGPORT=PRIVATE_INVALID",
			"EVYDENCE_S3_ENDPOINT=PRIVATE_INVALID/endpoint",
		} {
			if _, err := Prepare(roleEnvironment(t, Worker, false, entry), role); !errors.Is(err, ErrInvalidValue) {
				t.Fatal("operator accepted invalid runtime input", err)
			}
		}
		if _, err := Prepare(roleEnvironment(t, Worker, false, "EVYDENCE_DATABASE_URL="), role); !errors.Is(err, ErrMissingValue) {
			t.Fatal("operator did not require its database", err)
		}
	}
	for _, tc := range []struct {
		role           Role
		own, unrelated string
	}{
		{WorkerReplay, "EVYDENCE_PARSER_REPLAY_TIMEOUT", "EVYDENCE_RECONCILIATION_TIMEOUT"},
		{WorkerReconcile, "EVYDENCE_RECONCILIATION_TIMEOUT", "EVYDENCE_PARSER_REPLAY_TIMEOUT"},
	} {
		if _, err := Parse(roleEnvironment(t, Worker, false, tc.own+"=PRIVATE_INVALID"), tc.role); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("invalid applicable timeout accepted", err)
		}
		if _, err := Parse(roleEnvironment(t, Worker, false, tc.unrelated+"=PRIVATE_INVALID"), tc.role); err != nil {
			t.Fatal("operator evaluated another command's timeout", err)
		}
	}
}
