package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// These vectors freeze the complete policy result before moving its pure rules
// to the domain, including wording, ordering, missing IDs and UTC timestamps.
func TestReadinessCanonicalCompatibilityVectors(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	passing := passingReadinessSnapshot()
	failed := passing
	failed.HasSBOM = false
	failed.UnhandledCritical = true
	failed.UnhandledHigh = true
	failed.PackageCount = 2
	failed.MissingCustomerStatementIDs = []string{" d_2 ", "d_1", "d_2", ""}
	failed.MissingNotAffectedReasonIDs = []string{"d_3"}
	failed.IncompleteExceptionIDs = []string{"ex_2", "ex_1"}
	failed.InvalidPackageOrProfileIDs = []string{"pkg_2", "pkg_1"}
	for _, vector := range []struct {
		name  string
		facts ReadinessSnapshot
		want  string
	}{{"passing", passing, "b3d8823f182197004005fc59350a245759211c61b407a3b3b5f26236425790c6"}, {"failed", failed, "41fc279a878aeac8904e17c353f25a1e1d08cde582f2688cab5cabec03b4129a"}} {
		t.Run(vector.name, func(t *testing.T) {
			evaluation, err := EvaluateReadinessSnapshot(vector.facts, now)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(evaluation)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != vector.want {
				t.Fatalf("canonical policy vector changed: got %s want %s", got, vector.want)
			}
		})
	}
}

func TestReadinessDomainValidationKeepsApplicationErrorContract(t *testing.T) {
	facts := passingReadinessSnapshot()
	facts.SnapshotVersion = "future"
	if value, err := EvaluateReadinessSnapshot(facts, time.Unix(10, 0)); !errors.Is(err, ErrValidation) || value.Result != "" {
		t.Fatalf("application validation contract changed: %#v err=%v", value, err)
	}
}

func TestPreviewReadinessIsReadOnlyAndExplicitEvaluationPersists(t *testing.T) {
	state := newRiskTestState()
	state.readiness = passingReadinessSnapshot()
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	preview, err := service.PreviewReleaseReadiness(context.Background(), riskTestActor(), "rel_1")
	if err != nil {
		t.Fatalf("preview readiness: %v", err)
	}
	if preview.ID != "" || preview.Result != "passed" || len(preview.Checks) != 13 {
		t.Fatalf("preview = %#v", preview)
	}
	if len(state.evaluations) != 0 || len(state.audit) != 0 || state.executeCalls != 0 {
		t.Fatalf("preview mutated state: evaluations=%#v audit=%#v executes=%d", state.evaluations, state.audit, state.executeCalls)
	}

	evaluation, err := service.EvaluateRelease(context.Background(), riskTestActor(), "rel_1")
	if err != nil {
		t.Fatalf("evaluate readiness: %v", err)
	}
	if evaluation.ID != "pe_1" || state.evaluations[evaluation.ID].ReleaseID != "rel_1" || len(state.audit) != 1 {
		t.Fatalf("evaluation = %#v persisted=%#v audit=%#v", evaluation, state.evaluations, state.audit)
	}
}

func TestReadinessRejectsForeignOrInconsistentSnapshot(t *testing.T) {
	state := newRiskTestState()
	state.readiness = passingReadinessSnapshot()
	state.readiness.TenantID = "ten_2"
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Now())

	if _, err := service.PreviewReleaseReadiness(context.Background(), riskTestActor(), "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot error = %v", err)
	}
	if len(state.evaluations) != 0 || len(state.audit) != 0 {
		t.Fatalf("foreign snapshot mutated state")
	}
}

func TestEvaluateReadinessBuildsFailedPolicyFromFacts(t *testing.T) {
	state := newRiskTestState()
	state.readiness = passingReadinessSnapshot()
	state.readiness.HasSBOM = false
	state.readiness.UnhandledCritical = true
	state.readiness.IncompleteExceptionIDs = []string{"ex_2", "ex_1"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Now())

	preview, err := service.PreviewReleaseReadiness(context.Background(), riskTestActor(), "rel_1")
	if err != nil {
		t.Fatalf("preview readiness: %v", err)
	}
	if preview.Result != "failed" {
		t.Fatalf("result = %q", preview.Result)
	}
	checks := map[string]PolicyCheckView{}
	for _, check := range preview.Checks {
		checks[check.Name] = PolicyCheckView{Result: check.Result, Missing: check.Missing}
	}
	if checks["release_requires_sbom"].Result != "failed" || checks["critical_exploitable_blocks_release"].Result != "failed" {
		t.Fatalf("failed checks = %#v", checks)
	}
	if got := checks["exceptions_require_owner_reason_expiry_and_approval"].Missing; len(got) != 2 || got[0] != "ex_1" || got[1] != "ex_2" {
		t.Fatalf("sorted exception gaps = %#v", got)
	}
}

func TestPreviewReadinessRejectsMalformedSnapshotAndInvalidRequest(t *testing.T) {
	base := passingReadinessSnapshot()
	for _, tt := range []struct {
		name   string
		mutate func(*ReadinessSnapshot)
	}{
		{"unsupported version", func(s *ReadinessSnapshot) { s.SnapshotVersion = "future" }},
		{"foreign tenant", func(s *ReadinessSnapshot) { s.TenantID = "ten_2" }},
		{"wrong release", func(s *ReadinessSnapshot) { s.ReleaseID = "rel_2" }},
		{"missing product", func(s *ReadinessSnapshot) { s.ProductID = " " }},
		{"negative package count", func(s *ReadinessSnapshot) { s.PackageCount = -1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newRiskTestState()
			state.readiness = base
			tt.mutate(&state.readiness)
			service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Unix(10, 0))
			if _, err := service.PreviewReleaseReadiness(context.Background(), riskTestActor(), "rel_1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("malformed snapshot error = %v", err)
			}
			if state.executeCalls != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid preview persisted: executions=%d audit=%#v", state.executeCalls, state.audit)
			}
		})
	}
	state := newRiskTestState()
	state.readiness = base
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Unix(10, 0))
	if _, err := service.PreviewReleaseReadiness(context.Background(), riskTestActor(), " "); !errors.Is(err, ErrValidation) {
		t.Fatalf("blank release error = %v", err)
	}
}

func TestEvaluateReleaseRollsBackWhenAuditFails(t *testing.T) {
	state := newRiskTestState()
	state.readiness = passingReadinessSnapshot()
	state.auditErr = errRiskTestFailure
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Unix(10, 0))
	if _, err := service.EvaluateRelease(context.Background(), riskTestActor(), "rel_1"); !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("evaluation audit failure = %v", err)
	}
	if len(state.evaluations) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed evaluation published: evaluations=%#v audit=%#v", state.evaluations, state.audit)
	}
}

type PolicyCheckView struct {
	Result  string
	Missing []string
}

func passingReadinessSnapshot() ReadinessSnapshot {
	return ReadinessSnapshot{
		SnapshotVersion: ReadinessSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		HasArtifact: true, HasSBOM: true, HasVulnerabilityScan: true, HasArtifactDigest: true,
		HasVerifiedSignedBundle: true, HasPassedBuild: true, HasVerifiedBuildAttestation: true,
		PackageCount: 0,
	}
}
