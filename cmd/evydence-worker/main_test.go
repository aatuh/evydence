package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type fakeStateLoader struct {
	state app.PersistedState
	ok    bool
	err   error
}

func (f fakeStateLoader) LoadState(context.Context) (app.PersistedState, bool, error) {
	return f.state, f.ok, f.err
}

func TestProcessJobVerifiesConfiguredJobState(t *testing.T) {
	job := postgres.ClaimedJob{
		ID:          "job_test",
		TenantID:    "ten_test",
		Kind:        "verify_subject",
		SubjectType: "release_bundle",
		SubjectID:   "rb_test",
		Payload:     map[string]any{"result_id": "vr_test", "payload_ref": "object://tenants/ten_test/payloads/raw-secret-name"},
	}
	state := app.PersistedState{Verifications: map[string]domain.VerificationResult{
		"vr_test": {ID: "vr_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "rb_test", Result: "passed", VerifiedAt: time.Now().UTC()},
	}}
	if err := processJob(context.Background(), fakeStateLoader{state: state, ok: true}, job); err != nil {
		t.Fatalf("process configured verification job: %v", err)
	}
}

func TestProcessJobFailsSafelyWhenDurableStateIsMissing(t *testing.T) {
	job := postgres.ClaimedJob{
		ID:          "job_test",
		TenantID:    "ten_test",
		Kind:        "parse_sbom",
		SubjectType: "sbom",
		SubjectID:   "sbom_test",
		Payload:     map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom/raw-secret-name"},
	}
	err := processJob(context.Background(), fakeStateLoader{state: app.PersistedState{}, ok: true}, job)
	if err == nil {
		t.Fatal("expected recognized unhandled job to fail closed")
	}
	if !strings.Contains(err.Error(), "parsed sbom is not available") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "raw-secret-name") || strings.Contains(err.Error(), job.SubjectID) {
		t.Fatalf("job error leaked payload or subject: %v", err)
	}
}

func TestProcessJobRejectsUnsupportedKinds(t *testing.T) {
	err := processJob(context.Background(), fakeStateLoader{state: app.PersistedState{}, ok: true}, postgres.ClaimedJob{Kind: "unknown", Payload: map[string]any{"token": "secret"}})
	if err == nil {
		t.Fatal("expected unsupported job kind to fail")
	}
	if !strings.Contains(err.Error(), "unsupported outbox job kind") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected unsupported job error: %v", err)
	}
}
