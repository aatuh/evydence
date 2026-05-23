package main

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestProcessJobFailsClosedForConfiguredButUnhandledJobs(t *testing.T) {
	job := postgres.ClaimedJob{
		ID:          "job_test",
		TenantID:    "ten_test",
		Kind:        "parse_sbom",
		SubjectType: "sbom",
		SubjectID:   "sbom_test",
		Payload:     map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom/raw-secret-name"},
	}
	err := processJob(context.Background(), job)
	if err == nil {
		t.Fatal("expected recognized unhandled job to fail closed")
	}
	if !strings.Contains(err.Error(), "handler is not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "raw-secret-name") || strings.Contains(err.Error(), job.SubjectID) {
		t.Fatalf("job error leaked payload or subject: %v", err)
	}
}

func TestProcessJobRejectsUnsupportedKinds(t *testing.T) {
	err := processJob(context.Background(), postgres.ClaimedJob{Kind: "unknown", Payload: map[string]any{"token": "secret"}})
	if err == nil {
		t.Fatal("expected unsupported job kind to fail")
	}
	if !strings.Contains(err.Error(), "unsupported outbox job kind") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected unsupported job error: %v", err)
	}
}
