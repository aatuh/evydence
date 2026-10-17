package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func TestWorkerLoggingConfigurationFailsBeforeRuntime(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "host=PRIVATE_DATABASE")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_LOG_FORMAT", "CANARY_SECRET")
	err := run()
	if !errors.Is(err, config.ErrInvalidValue) || strings.Contains(err.Error(), "CANARY_SECRET") {
		t.Fatal("logging was not safely validated before runtime")
	}
}

func TestWorkerLoggingRestoresDurableRequestAndOmitsPayloadLeaseAndFailure(t *testing.T) {
	for _, failure := range []error{nil, errors.New("CANARY_RAW_PROVIDER_ERROR")} {
		var out bytes.Buffer
		logger, err := logging.New(&out, "worker", runtimeinfo.Current(), logging.Config{})
		if err != nil {
			t.Fatal(err)
		}
		origin := logging.WithOperation(logging.WithRequest(t.Context(), "CANARY_HTTP_REQUEST"), "uploadSBOM")
		correlation := logging.CorrelationFromContext(origin)
		job := postgres.ClaimedJob{Correlation: correlation, ID: "CANARY_JOB", TenantID: "CANARY_TENANT", SubjectID: "CANARY_RESOURCE", Kind: "parse_sbom", LeaseToken: "CANARY_LEASE", Payload: map[string]any{"evidence": "CANARY_RAW_BODY"}}
		queue := &lifecycleQueue{}
		processor := lifecycleProcessor(func(ctx context.Context, _ postgres.ClaimedJob) error {
			if logging.CorrelationFromContext(ctx) != correlation {
				t.Fatal("processor lost source correlation")
			}
			return failure
		})
		if err := drainableWorkerJob(logging.WithLogger(t.Context(), logger), queue, processor, job, time.Second); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "CANARY") {
			t.Fatal("worker secret leaked")
		}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			if event["request_id"] != correlation.RequestID || event["operation_id"] != correlation.OperationID {
				t.Fatal("worker observation lost originating request/operation")
			}
		}
	}
}
