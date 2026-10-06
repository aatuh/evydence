package domain

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func readinessFacts() ReadinessSnapshot {
	return ReadinessSnapshot{
		SnapshotVersion: ReadinessSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		HasArtifact: true, HasSBOM: true, HasVulnerabilityScan: true, HasArtifactDigest: true,
		HasVerifiedSignedBundle: true, HasPassedBuild: true, HasVerifiedBuildAttestation: true,
	}
}

func TestReadinessPolicyUsesThirteenChecksAndDoesNotMutateFacts(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	facts := readinessFacts()
	evaluation, err := EvaluateReadinessSnapshot(facts, now)
	if err != nil || evaluation.ID != "" || evaluation.Result != "passed" || evaluation.PolicySet != PolicySetVersion || len(evaluation.Checks) != 13 || evaluation.TenantID != facts.TenantID || evaluation.ReleaseID != facts.ReleaseID || evaluation.CreatedAt.Location() != time.UTC || !evaluation.CreatedAt.Equal(now) {
		t.Fatalf("invalid policy result: %#v err=%v", evaluation, err)
	}
	for _, check := range evaluation.Checks {
		if check.Result != "passed" || check.Explanation == "" || len(check.Missing) != 0 {
			t.Fatalf("passing fact failed: %#v", check)
		}
	}
	facts.MissingCustomerStatementIDs = []string{" d_2 ", "d_1", "d_2", ""}
	original := append([]string(nil), facts.MissingCustomerStatementIDs...)
	evaluation, err = EvaluateReadinessSnapshot(facts, now)
	if err != nil || evaluation.Result != "failed" {
		t.Fatalf("missing statements accepted: %#v err=%v", evaluation, err)
	}
	check := evaluation.Checks[9]
	if check.Name != "customer_visible_decisions_require_statements" || !reflect.DeepEqual(check.Missing, []string{"d_1", "d_2"}) || !reflect.DeepEqual(facts.MissingCustomerStatementIDs, original) {
		t.Fatalf("canonical gaps or source mutated: %#v facts=%#v", check, facts)
	}
	check.Missing[0] = "mutated"
	if !reflect.DeepEqual(facts.MissingCustomerStatementIDs, original) {
		t.Fatal("policy result aliases source facts")
	}
}

func TestReadinessPolicyRejectsInvalidSnapshotWithoutResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ReadinessSnapshot)
	}{
		{"version", func(s *ReadinessSnapshot) { s.SnapshotVersion = "future" }},
		{"tenant", func(s *ReadinessSnapshot) { s.TenantID = "" }},
		{"product", func(s *ReadinessSnapshot) { s.ProductID = "" }},
		{"release", func(s *ReadinessSnapshot) { s.ReleaseID = "" }},
		{"package count", func(s *ReadinessSnapshot) { s.PackageCount = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := readinessFacts()
			tc.change(&facts)
			if value, err := EvaluateReadinessSnapshot(facts, time.Unix(10, 0)); !errors.Is(err, ErrReadinessValidation) || value.Result != "" || len(value.Checks) != 0 {
				t.Fatalf("invalid snapshot yielded policy: %#v err=%v", value, err)
			}
		})
	}
	if value, err := EvaluateReadinessSnapshot(readinessFacts(), time.Time{}); !errors.Is(err, ErrReadinessValidation) || value.Result != "" {
		t.Fatalf("zero clock accepted: %#v err=%v", value, err)
	}
}

func TestReadinessPolicyDistinguishesAbsentValidAndInvalidPackages(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		invalid  []string
		result   string
		severity string
		missing  []string
	}{
		{"no package", 0, nil, "passed", "medium", nil},
		{"valid package", 1, nil, "passed", "high", nil},
		{"invalid package", 1, []string{" p_2 ", "p_1", "p_2"}, "failed", "high", []string{"p_1", "p_2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := readinessFacts()
			facts.PackageCount, facts.InvalidPackageOrProfileIDs = tc.count, tc.invalid
			value, err := EvaluateReadinessSnapshot(facts, time.Unix(10, 0))
			if err != nil {
				t.Fatal(err)
			}
			check := value.Checks[12]
			if check.Name != "package_redaction_profile_valid" || check.Result != tc.result || check.Severity != tc.severity || !reflect.DeepEqual(check.Missing, tc.missing) || value.Result != tc.result {
				t.Fatalf("package policy changed: %#v", value)
			}
		})
	}
}
