package app

import (
	"context"
	"errors"
	"testing"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestReleaseReadinessReportIsReadOnlyAndUsesCommittedSnapshot(t *testing.T) {
	state := newPackageTestState()
	state.readinessReport = ReadinessReportSnapshot{
		SnapshotVersion: ReadinessReportSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Result: "failed", PolicySet: "policy-set.v1.0.0",
		Checks: []packagedomain.PolicyCheckSnapshot{
			{Name: "release_has_artifact", Result: "passed", Severity: "high"},
			{Name: "release_requires_sbom", Result: "failed", Severity: "high", Missing: []string{"sbom"}},
			{Name: "critical_exploitable_blocks_release", Result: "failed", Severity: "critical", Missing: []string{"vulnerability_decision"}},
		},
		BlockingFindings:    []packagedomain.BlockingFinding{{FindingID: "finding_1", ReleaseID: "rel_1", Severity: "critical"}},
		ActiveDecisionCount: 1,
	}
	service := newPackageTestService(t, state)

	report, err := service.ReleaseReadinessReport(context.Background(), packageTestActor(), "rel_1")
	if err != nil {
		t.Fatalf("release readiness report: %v", err)
	}
	if report.Result != "failed" || len(report.Sections) != 5 || len(report.BlockingFindings) != 1 || len(report.Gaps) != 2 {
		t.Fatalf("report = %#v", report)
	}
	if state.readinessReportReads != 1 || state.executeCalls != 0 || len(state.audit) != 0 {
		t.Fatalf("report mutated state: reads=%d executes=%d audit=%#v", state.readinessReportReads, state.executeCalls, state.audit)
	}
}

func TestReleaseReadinessReportRejectsInconsistentSnapshotWithoutPublishing(t *testing.T) {
	base := ReadinessReportSnapshot{
		SnapshotVersion: ReadinessReportSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Result: "passed", PolicySet: "policy-set.v1",
	}
	for _, tt := range []struct {
		name   string
		mutate func(*ReadinessReportSnapshot)
	}{
		{"unsupported version", func(s *ReadinessReportSnapshot) { s.SnapshotVersion = "future" }},
		{"missing product", func(s *ReadinessReportSnapshot) { s.ProductID = " " }},
		{"negative decision count", func(s *ReadinessReportSnapshot) { s.ActiveDecisionCount = -1 }},
		{"invalid result", func(s *ReadinessReportSnapshot) { s.Result = "unknown" }},
		{"missing policy set", func(s *ReadinessReportSnapshot) { s.PolicySet = " " }},
		{"unnamed check", func(s *ReadinessReportSnapshot) { s.Checks = []packagedomain.PolicyCheckSnapshot{{Result: "passed"}} }},
		{"invalid check result", func(s *ReadinessReportSnapshot) {
			s.Checks = []packagedomain.PolicyCheckSnapshot{{Name: "check", Result: "unknown"}}
		}},
		{"cross-release finding", func(s *ReadinessReportSnapshot) {
			s.BlockingFindings = []packagedomain.BlockingFinding{{FindingID: "finding_1", ReleaseID: "rel_2"}}
		}},
		{"cross-tenant exception", func(s *ReadinessReportSnapshot) {
			s.AcceptedExceptions = []packagedomain.AcceptedExceptionSnapshot{{ID: "ex_1", TenantID: "ten_2", ReleaseID: "rel_1", Approved: true}}
		}},
		{"unapproved exception", func(s *ReadinessReportSnapshot) {
			s.AcceptedExceptions = []packagedomain.AcceptedExceptionSnapshot{{ID: "ex_1", TenantID: "ten_1", ReleaseID: "rel_1"}}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newPackageTestState()
			state.readinessReport = base
			tt.mutate(&state.readinessReport)
			service := newPackageTestService(t, state)
			if _, err := service.ReleaseReadinessReport(context.Background(), packageTestActor(), "rel_1"); !errors.Is(err, ErrConflict) {
				t.Fatalf("inconsistent report error = %v", err)
			}
			if state.executeCalls != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid snapshot published writes: executions=%d audit=%#v", state.executeCalls, state.audit)
			}
		})
	}
}

func TestReleaseReadinessReportPassedSnapshotUsesDecisionAndExceptionEvidence(t *testing.T) {
	state := newPackageTestState()
	state.readinessReport = ReadinessReportSnapshot{
		SnapshotVersion: ReadinessReportSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Result: "passed", PolicySet: "policy-set.v1", ActiveDecisionCount: 2, HasActiveCustomerPackage: true,
		AcceptedExceptions: []packagedomain.AcceptedExceptionSnapshot{{ID: "ex_1", TenantID: "ten_1", ReleaseID: "rel_1", Approved: true}},
	}
	service := newPackageTestService(t, state)
	report, err := service.ReleaseReadinessReport(context.Background(), packageTestActor(), "rel_1")
	if err != nil || report.Result != "passed" || len(report.Gaps) != 0 {
		t.Fatalf("passed report = %#v, %v", report, err)
	}
	riskQuestions := report.Sections[1].Questions
	if riskQuestions[2].Status != "passed" || riskQuestions[5].Status != "passed" || report.Sections[3].Questions[0].Status != "passed" {
		t.Fatalf("decision, exception, or customer-package evidence omitted: %#v", report.Sections)
	}
	if state.executeCalls != 0 || len(state.audit) != 0 {
		t.Fatalf("read-only report published writes: executions=%d audit=%#v", state.executeCalls, state.audit)
	}
}

func TestReleaseReadinessReportRejectsForeignSnapshot(t *testing.T) {
	state := newPackageTestState()
	state.readinessReport = ReadinessReportSnapshot{SnapshotVersion: ReadinessReportSnapshotVersion, TenantID: "ten_2", ProductID: "prod_2", ReleaseID: "rel_1"}
	service := newPackageTestService(t, state)
	if _, err := service.ReleaseReadinessReport(context.Background(), packageTestActor(), "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot error = %v", err)
	}
}
