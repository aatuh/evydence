package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var errRiskTestFailure = errors.New("risk test failure")

func TestCreateVulnerabilityDecisionSupersedesAtomically(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.findings["finding_1"] = FindingReference{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", ProductID: "prod_1", Vulnerability: "CVE-2026-0001", Component: "pkg:generic/api@1", Severity: "critical"}
	status, err := riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusAffectedValue)
	if err != nil {
		t.Fatal(err)
	}
	state.decisions["vd_old"] = riskdomain.VulnerabilityDecision{ID: "vd_old", TenantID: "ten_1", FindingID: "finding_1", ScanID: "scan_1", ReleaseID: "rel_1", Vulnerability: "CVE-2026-0001", Component: "pkg:generic/api@1", Status: status, Justification: "triage", CreatedAt: now.Add(-time.Hour)}
	state.evidence["ev_1"] = EvidenceReference{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	decision, err := service.CreateVulnerabilityDecision(context.Background(), riskTestActor(), "finding_1", CreateVulnerabilityDecisionInput{
		Status: riskdomain.DecisionStatusFixedValue, Justification: "patched", EvidenceIDs: []string{" ev_1 ", "ev_1"},
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}
	if decision.ID != "vd_1" || decision.Supersedes != "vd_old" || !reflect.DeepEqual(decision.EvidenceIDs, []string{"ev_1"}) {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if got := state.decisions["vd_old"].SupersededBy; got != decision.ID {
		t.Fatalf("prior superseded_by = %q", got)
	}
	if len(state.audit) != 2 || state.audit[0].EntryType != "vulnerability_decision.superseded" || state.audit[1].EntryType != "vulnerability_decision.created" {
		t.Fatalf("unexpected audit events: %#v", state.audit)
	}
	if state.executeCalls != 1 {
		t.Fatalf("transaction executions = %d", state.executeCalls)
	}
}

func TestCreateVulnerabilityDecisionRollsBackMutationWhenAuditFails(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.findings["finding_1"] = FindingReference{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", ProductID: "prod_1", Vulnerability: "CVE-2026-0001", Component: "api"}
	state.auditErr = errRiskTestFailure
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	_, err := service.CreateVulnerabilityDecision(context.Background(), riskTestActor(), "finding_1", CreateVulnerabilityDecisionInput{Status: riskdomain.DecisionStatusFixedValue, Justification: "patched"})
	if !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("error = %v", err)
	}
	if len(state.decisions) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed transaction published state: decisions=%#v audit=%#v", state.decisions, state.audit)
	}
}

func TestCreateVulnerabilityDecisionRejectsForeignReferencesAndUnsafeReviewMetadata(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.findings["foreign"] = FindingReference{ID: "foreign", TenantID: "ten_2", ReleaseID: "rel_2", ProductID: "prod_2"}
	state.findings["finding_1"] = FindingReference{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", ProductID: "prod_1", Vulnerability: "CVE-2026-0001", Component: "api"}
	state.evidence["foreign_evidence"] = EvidenceReference{ID: "foreign_evidence", TenantID: "ten_2", ReleaseID: "rel_1"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	tests := []struct {
		name      string
		findingID string
		input     CreateVulnerabilityDecisionInput
		want      error
	}{
		{name: "foreign finding", findingID: "foreign", input: CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched"}, want: ErrNotFound},
		{name: "foreign evidence", findingID: "finding_1", input: CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched", EvidenceIDs: []string{"foreign_evidence"}}, want: ErrNotFound},
		{name: "future review", findingID: "finding_1", input: CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched", ReviewedAt: timePointer(now.Add(2 * time.Minute))}, want: ErrValidation},
		{name: "due before review", findingID: "finding_1", input: CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched", ReviewedAt: timePointer(now), ReviewDueAt: timePointer(now.Add(-time.Minute))}, want: ErrValidation},
		{name: "customer visible without impact", findingID: "finding_1", input: CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched", CustomerVisible: true}, want: ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.CreateVulnerabilityDecision(context.Background(), riskTestActor(), tt.findingID, tt.input)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestListVulnerabilityDecisionsFiltersForbiddenAndPropagatesPolicyFailure(t *testing.T) {
	state := newRiskTestState()
	fixed, _ := riskdomain.ParseDecisionStatus("fixed")
	state.decisions["vd_1"] = riskdomain.VulnerabilityDecision{ID: "vd_1", TenantID: "ten_1", ReleaseID: "rel_1", Status: fixed, CreatedAt: time.Unix(1, 0)}
	state.decisions["vd_2"] = riskdomain.VulnerabilityDecision{ID: "vd_2", TenantID: "ten_1", ReleaseID: "rel_2", Status: fixed, CreatedAt: time.Unix(2, 0)}
	state.decisions["vd_foreign"] = riskdomain.VulnerabilityDecision{ID: "vd_foreign", TenantID: "ten_2", ReleaseID: "rel_1", Status: fixed}
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.releases["rel_2"] = ReleaseReference{ID: "rel_2", TenantID: "ten_1", ProductID: "prod_1"}
	authorizer := riskTestAuthorizer{denyRelease: "rel_2"}
	service := newRiskTestService(t, state, authorizer, time.Unix(10, 0))

	got, err := service.ListVulnerabilityDecisions(context.Background(), riskTestActor(), ListVulnerabilityDecisionsInput{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID != "vd_1" {
		t.Fatalf("unexpected decisions: %#v", got)
	}

	authorizer.operationalErr = errRiskTestFailure
	service = newRiskTestService(t, state, authorizer, time.Unix(10, 0))
	if _, err := service.ListVulnerabilityDecisions(context.Background(), riskTestActor(), ListVulnerabilityDecisionsInput{}); !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("operational authorization error = %v", err)
	}
}

func TestListVulnerabilityDecisionsAppliesExactFiltersAndRejectsMismatchedScope(t *testing.T) {
	state := newRiskTestState()
	state.products["prod_1"] = ProductReference{ID: "prod_1", TenantID: "ten_1"}
	state.products["prod_2"] = ProductReference{ID: "prod_2", TenantID: "ten_1"}
	state.products["foreign"] = ProductReference{ID: "foreign", TenantID: "ten_2"}
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.releases["rel_2"] = ReleaseReference{ID: "rel_2", TenantID: "ten_1", ProductID: "prod_2"}
	fixed, _ := riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusFixedValue)
	affected, _ := riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusAffectedValue)
	state.decisions["vd_active"] = riskdomain.VulnerabilityDecision{ID: "vd_active", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-2026-0001", Component: "pkg:api", Status: fixed}
	state.decisions["vd_old"] = riskdomain.VulnerabilityDecision{ID: "vd_old", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-2026-0001", Component: "pkg:api", Status: fixed, SupersededBy: "vd_active"}
	state.decisions["vd_other"] = riskdomain.VulnerabilityDecision{ID: "vd_other", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-2026-0002", Component: "pkg:other", Status: affected}
	state.decisions["vd_second_product"] = riskdomain.VulnerabilityDecision{ID: "vd_second_product", TenantID: "ten_1", ReleaseID: "rel_2", Status: fixed}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Unix(10, 0))
	active, inactive := true, false
	base := ListVulnerabilityDecisionsInput{ProductID: " prod_1 ", ReleaseID: " rel_1 ", Vulnerability: " CVE-2026-0001 ", Component: " pkg:api ", Status: " fixed "}

	query := base
	query.Active = &active
	got, err := service.ListVulnerabilityDecisions(context.Background(), riskTestActor(), query)
	if err != nil || len(got) != 1 || got[0].ID != "vd_active" {
		t.Fatalf("active exact filter = %#v, %v", got, err)
	}
	query.Active = &inactive
	got, err = service.ListVulnerabilityDecisions(context.Background(), riskTestActor(), query)
	if err != nil || len(got) != 1 || got[0].ID != "vd_old" {
		t.Fatalf("inactive exact filter = %#v, %v", got, err)
	}
	for _, tt := range []struct {
		name  string
		query ListVulnerabilityDecisionsInput
		want  error
	}{
		{name: "invalid status", query: ListVulnerabilityDecisionsInput{Status: "invented"}, want: ErrValidation},
		{name: "foreign product", query: ListVulnerabilityDecisionsInput{ProductID: "foreign"}, want: ErrNotFound},
		{name: "missing release", query: ListVulnerabilityDecisionsInput{ReleaseID: "missing"}, want: ErrNotFound},
		{name: "mismatched product and release", query: ListVulnerabilityDecisionsInput{ProductID: "prod_1", ReleaseID: "rel_2"}, want: ErrNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := service.ListVulnerabilityDecisions(context.Background(), riskTestActor(), tt.query); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCreateVulnerabilityDecisionValidatesVEXEvidenceAndSupportingReferences(t *testing.T) {
	state := newRiskTestState()
	state.findings["finding_1"] = FindingReference{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", ProductID: "prod_1", Vulnerability: "CVE-2026-0001", Component: "pkg:api"}
	state.vex["vex_1"] = VEXReference{ID: "vex_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.vex["vex_other_release"] = VEXReference{ID: "vex_other_release", TenantID: "ten_1", ReleaseID: "rel_2"}
	state.evidence["ev_1"] = EvidenceReference{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.evidence["ev_other_release"] = EvidenceReference{ID: "ev_other_release", TenantID: "ten_1", ReleaseID: "rel_2"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, time.Unix(10, 0))
	base := CreateVulnerabilityDecisionInput{Status: riskdomain.DecisionStatusFixedValue, Justification: "patched"}

	for _, tt := range []struct {
		name  string
		input CreateVulnerabilityDecisionInput
		want  error
	}{
		{name: "foreign-release VEX", input: CreateVulnerabilityDecisionInput{Status: base.Status, Justification: base.Justification, VEXDocumentID: "vex_other_release"}, want: ErrNotFound},
		{name: "foreign-release evidence", input: CreateVulnerabilityDecisionInput{Status: base.Status, Justification: base.Justification, EvidenceIDs: []string{"ev_other_release"}}, want: ErrNotFound},
		{name: "supporting reference with digest", input: CreateVulnerabilityDecisionInput{Status: base.Status, Justification: base.Justification, SupportingRefs: []riskdomain.SupportingReference{{Type: "approval", ID: "apr_1", Digest: "sha256:untrusted"}}}, want: ErrValidation},
		{name: "duplicate supporting reference", input: CreateVulnerabilityDecisionInput{Status: base.Status, Justification: base.Justification, SupportingRefs: []riskdomain.SupportingReference{{Type: "approval", ID: "apr_1"}, {Type: " approval ", ID: " apr_1 "}}}, want: ErrValidation},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := service.CreateVulnerabilityDecision(context.Background(), riskTestActor(), "finding_1", tt.input); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
	if len(state.decisions) != 0 || len(state.audit) != 0 {
		t.Fatalf("invalid references published decision or audit: decisions=%#v audit=%#v", state.decisions, state.audit)
	}

	input := base
	input.VEXDocumentID = "vex_1"
	input.EvidenceIDs = []string{"ev_1"}
	input.SupportingRefs = []riskdomain.SupportingReference{{Type: " Approval ", ID: " apr_1 "}}
	decision, err := service.CreateVulnerabilityDecision(context.Background(), riskTestActor(), "finding_1", input)
	if err != nil || decision.VEXDocumentID != "vex_1" || !reflect.DeepEqual(decision.EvidenceIDs, []string{"ev_1"}) || len(decision.SupportingRefs) != 1 || decision.SupportingRefs[0].Type != "approval" || decision.SupportingRefs[0].ID != "apr_1" {
		t.Fatalf("validated decision = %#v, %v", decision, err)
	}
}

func TestVulnerabilityDecisionSummaryReportIncludesOnlyActiveCustomerVisibleDecisions(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.releases["foreign"] = ReleaseReference{ID: "foreign", TenantID: "ten_2", ProductID: "prod_2"}
	fixed, _ := riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusFixedValue)
	base := riskdomain.VulnerabilityDecision{
		TenantID: "ten_1", ReleaseID: "rel_1", Status: fixed, CustomerVisible: true,
		Vulnerability: "CVE-2026-0001", Justification: "patched", InternalNotes: "internal-secret",
		EvidenceIDs: []string{"ev_1"}, CreatedAt: now.Add(-time.Hour),
	}
	first := base
	first.ID = "vd_1"
	second := base
	second.ID = "vd_2"
	second.CreatedAt = now
	hidden := base
	hidden.ID = "vd_hidden"
	hidden.CustomerVisible = false
	superseded := base
	superseded.ID = "vd_old"
	superseded.SupersededBy = "vd_2"
	otherRelease := base
	otherRelease.ID = "vd_other_release"
	otherRelease.ReleaseID = "rel_2"
	foreign := base
	foreign.ID = "vd_foreign"
	foreign.TenantID = "ten_2"
	for _, decision := range []riskdomain.VulnerabilityDecision{first, second, hidden, superseded, otherRelease, foreign} {
		state.decisions[decision.ID] = decision
	}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	report, err := service.VulnerabilityDecisionSummaryReport(context.Background(), riskTestActor(), " rel_1 ")
	if err != nil {
		t.Fatalf("summary report: %v", err)
	}
	if report.ProductID != "prod_1" || report.ReleaseID != "rel_1" || !report.GeneratedAt.Equal(now) || len(report.Decisions) != 2 || report.Decisions[0].ID != "vd_1" || report.Decisions[1].ID != "vd_2" {
		t.Fatalf("summary scope/order = %#v", report)
	}
	if report.Decisions[0].Status != riskdomain.DecisionStatusFixedValue || !reflect.DeepEqual(report.Decisions[0].EvidenceIDs, []string{"ev_1"}) || len(report.Assumptions) == 0 || len(report.Limitations) == 0 {
		t.Fatalf("summary content = %#v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), "internal-secret") || len(state.audit) != 0 {
		t.Fatalf("summary leaked internal notes or persisted a read: json=%s audit=%#v err=%v", encoded, state.audit, err)
	}
	if _, err := service.VulnerabilityDecisionSummaryReport(context.Background(), riskTestActor(), "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign release error = %v", err)
	}
	denied := newRiskTestService(t, state, riskTestAuthorizer{denyRelease: "rel_1"}, now)
	if _, err := denied.VulnerabilityDecisionSummaryReport(context.Background(), riskTestActor(), "rel_1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized report error = %v", err)
	}
}

func TestListExceptionsFiltersTenantReleaseAndAuthorization(t *testing.T) {
	state := newRiskTestState()
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.releases["rel_2"] = ReleaseReference{ID: "rel_2", TenantID: "ten_1", ProductID: "prod_1"}
	state.exceptions["ex_1"] = riskdomain.Exception{ID: "ex_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: time.Unix(1, 0)}
	state.exceptions["ex_2"] = riskdomain.Exception{ID: "ex_2", TenantID: "ten_1", ReleaseID: "rel_2", CreatedAt: time.Unix(2, 0)}
	state.exceptions["ex_missing"] = riskdomain.Exception{ID: "ex_missing", TenantID: "ten_1", ReleaseID: "missing"}
	state.exceptions["ex_foreign"] = riskdomain.Exception{ID: "ex_foreign", TenantID: "ten_2", ReleaseID: "rel_1"}
	service := newRiskTestService(t, state, riskTestAuthorizer{denyRelease: "rel_2"}, time.Unix(10, 0))

	for _, releaseID := range []string{"", " rel_1 "} {
		got, err := service.ListExceptions(context.Background(), riskTestActor(), releaseID)
		if err != nil || len(got) != 1 || got[0].ID != "ex_1" {
			t.Fatalf("list exceptions for %q = %#v, %v", releaseID, got, err)
		}
	}
	if _, err := service.ListExceptions(context.Background(), riskTestActor(), "rel_2"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden release error = %v", err)
	}
	if _, err := service.ListExceptions(context.Background(), riskTestActor(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing release error = %v", err)
	}
	failing := newRiskTestService(t, state, riskTestAuthorizer{denyRelease: "rel_2", operationalErr: errRiskTestFailure}, time.Unix(10, 0))
	if _, err := failing.ListExceptions(context.Background(), riskTestActor(), ""); !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("authorization backend failure = %v", err)
	}
}

func TestExceptionLifecycleIsTenantScopedAndAtomic(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.findings["finding_1"] = FindingReference{ID: "finding_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.controls["ctl_1"] = ControlReference{ID: "ctl_1", TenantID: "ten_1"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	exception, err := service.CreateException(context.Background(), riskTestActor(), CreateExceptionInput{
		ReleaseID: "rel_1", FindingID: "finding_1", ControlID: "ctl_1", Reason: "accepted temporarily", Owner: "security", ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create exception: %v", err)
	}
	approved, err := service.ApproveException(context.Background(), riskTestActor(), exception.ID)
	if err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	if !approved.Approved || approved.ApprovedBy != "usr_1" || approved.ApprovedAt == nil {
		t.Fatalf("unexpected approved exception: %#v", approved)
	}
	again, err := service.ApproveException(context.Background(), riskTestActor(), exception.ID)
	if err != nil || !reflect.DeepEqual(again, approved) {
		t.Fatalf("idempotent approval = %#v, %v", again, err)
	}
	if len(state.audit) != 2 {
		t.Fatalf("audit events = %#v", state.audit)
	}
}

func TestCreateExceptionRejectsCrossReleaseFindingAndForeignControl(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.findings["other_release"] = FindingReference{ID: "other_release", TenantID: "ten_1", ReleaseID: "rel_2"}
	state.controls["foreign"] = ControlReference{ID: "foreign", TenantID: "ten_2"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)
	base := CreateExceptionInput{ReleaseID: "rel_1", Reason: "temporary", Owner: "security", ExpiresAt: now.Add(time.Hour)}
	for _, tt := range []struct {
		name   string
		mutate func(*CreateExceptionInput)
		want   error
	}{
		{"expired", func(v *CreateExceptionInput) { v.ExpiresAt = now }, ErrValidation},
		{"missing release", func(v *CreateExceptionInput) { v.ReleaseID = "missing" }, ErrNotFound},
		{"cross-release finding", func(v *CreateExceptionInput) { v.FindingID = "other_release" }, ErrNotFound},
		{"foreign control", func(v *CreateExceptionInput) { v.ControlID = "foreign" }, ErrNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := base
			tt.mutate(&input)
			if _, err := service.CreateException(context.Background(), riskTestActor(), input); !errors.Is(err, tt.want) {
				t.Fatalf("exception error = %v, want %v", err, tt.want)
			}
			if len(state.exceptions) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid exception persisted: exceptions=%#v audit=%#v", state.exceptions, state.audit)
			}
		})
	}
	state.auditErr = errRiskTestFailure
	if _, err := service.CreateException(context.Background(), riskTestActor(), base); !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.exceptions) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed audit published exception: exceptions=%#v audit=%#v", state.exceptions, state.audit)
	}
}

func TestApproveExceptionRejectsExpiredForeignAndMissingRelease(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.releases["rel_1"] = ReleaseReference{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}
	state.exceptions["expired"] = riskdomain.Exception{ID: "expired", TenantID: "ten_1", ReleaseID: "rel_1", ExpiresAt: now}
	state.exceptions["foreign"] = riskdomain.Exception{ID: "foreign", TenantID: "ten_2", ReleaseID: "rel_1", ExpiresAt: now.Add(time.Hour)}
	state.exceptions["orphan"] = riskdomain.Exception{ID: "orphan", TenantID: "ten_1", ReleaseID: "missing", ExpiresAt: now.Add(time.Hour)}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)
	for _, tt := range []struct {
		id   string
		want error
	}{{"expired", ErrConflict}, {"foreign", ErrNotFound}, {"orphan", ErrNotFound}} {
		if _, err := service.ApproveException(context.Background(), riskTestActor(), tt.id); !errors.Is(err, tt.want) {
			t.Fatalf("approve %q error = %v, want %v", tt.id, err, tt.want)
		}
	}
	if len(state.audit) != 0 {
		t.Fatalf("invalid exception approval was audited: %#v", state.audit)
	}
}

func newRiskTestService(t *testing.T, state *riskTestState, authorizer application.Authorizer, now time.Time) *Service {
	t.Helper()
	service, err := NewService(Config{
		Reader: state, Transactions: state, Authorizer: authorizer,
		Clock: application.ClockFunc(func() time.Time { return now }),
		IDs: application.IDGeneratorFunc(func(prefix string) string {
			switch prefix {
			case "vd":
				return "vd_1"
			case "ex":
				return "ex_1"
			default:
				return prefix + "_1"
			}
		}),
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func riskTestActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", KeyID: "key_1", Scopes: []string{"evidence:write", "evidence:read", "release:write", "verify:read"}}
}

func timePointer(value time.Time) *time.Time { return &value }

type allowRiskAuthorizer struct{}

func (allowRiskAuthorizer) Authorize(context.Context, identitydomain.Actor, application.AuthorizationRequest) error {
	return nil
}

type riskTestAuthorizer struct {
	denyRelease    string
	operationalErr error
}

func (a riskTestAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.ScopeOnly || request.TenantWide {
		return nil
	}
	if request.Resources.ReleaseID == a.denyRelease {
		if a.operationalErr != nil {
			return a.operationalErr
		}
		return application.ErrForbidden
	}
	return nil
}

type riskTestState struct {
	findings     map[string]FindingReference
	products     map[string]ProductReference
	releases     map[string]ReleaseReference
	evidence     map[string]EvidenceReference
	vex          map[string]VEXReference
	controls     map[string]ControlReference
	subjects     map[string]GovernanceSubjectReference
	decisions    map[string]riskdomain.VulnerabilityDecision
	exceptions   map[string]riskdomain.Exception
	waivers      map[string]riskdomain.Waiver
	approvals    map[string]riskdomain.ApprovalRecord
	readiness    ReadinessSnapshot
	evaluations  map[string]riskdomain.PolicyEvaluation
	audit        []application.AuditEvent
	auditErr     error
	executeCalls int
}

func newRiskTestState() *riskTestState {
	return &riskTestState{
		findings: map[string]FindingReference{}, products: map[string]ProductReference{}, releases: map[string]ReleaseReference{}, evidence: map[string]EvidenceReference{},
		vex: map[string]VEXReference{}, controls: map[string]ControlReference{}, subjects: map[string]GovernanceSubjectReference{},
		decisions: map[string]riskdomain.VulnerabilityDecision{}, exceptions: map[string]riskdomain.Exception{}, waivers: map[string]riskdomain.Waiver{}, approvals: map[string]riskdomain.ApprovalRecord{}, evaluations: map[string]riskdomain.PolicyEvaluation{},
	}
}

func (s *riskTestState) clone() *riskTestState {
	clone := newRiskTestState()
	for key, value := range s.findings {
		clone.findings[key] = value
	}
	for key, value := range s.products {
		clone.products[key] = value
	}
	for key, value := range s.releases {
		clone.releases[key] = value
	}
	for key, value := range s.evidence {
		clone.evidence[key] = value
	}
	for key, value := range s.vex {
		clone.vex[key] = value
	}
	for key, value := range s.controls {
		clone.controls[key] = value
	}
	for key, value := range s.subjects {
		clone.subjects[key] = value
	}
	for key, value := range s.decisions {
		clone.decisions[key] = cloneDecision(value)
	}
	for key, value := range s.exceptions {
		clone.exceptions[key] = cloneException(value)
	}
	for key, value := range s.waivers {
		clone.waivers[key] = cloneWaiver(value)
	}
	for key, value := range s.approvals {
		clone.approvals[key] = value
	}
	clone.readiness = cloneReadinessSnapshot(s.readiness)
	for key, value := range s.evaluations {
		clone.evaluations[key] = clonePolicyEvaluation(value)
	}
	clone.audit = append([]application.AuditEvent(nil), s.audit...)
	clone.auditErr = s.auditErr
	return clone
}

func (s *riskTestState) Execute(ctx context.Context, command TransactionCommand) error {
	s.executeCalls++
	working := s.clone()
	if err := command(ctx, riskTestTransaction{state: working}); err != nil {
		return err
	}
	s.findings, s.products, s.releases, s.evidence, s.vex, s.controls, s.subjects = working.findings, working.products, working.releases, working.evidence, working.vex, working.controls, working.subjects
	s.decisions, s.exceptions, s.audit = working.decisions, working.exceptions, working.audit
	s.waivers, s.approvals = working.waivers, working.approvals
	s.readiness, s.evaluations = working.readiness, working.evaluations
	return nil
}

func (s *riskTestState) ResolveFinding(_ context.Context, tenantID, id string) (FindingReference, error) {
	value, ok := s.findings[id]
	if !ok || value.TenantID != tenantID {
		return FindingReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) GetProduct(_ context.Context, tenantID, id string) (ProductReference, error) {
	value, ok := s.products[id]
	if !ok || value.TenantID != tenantID {
		return ProductReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) GetRelease(_ context.Context, tenantID, id string) (ReleaseReference, error) {
	value, ok := s.releases[id]
	if !ok || value.TenantID != tenantID {
		return ReleaseReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) GetEvidence(_ context.Context, tenantID, id string) (EvidenceReference, error) {
	value, ok := s.evidence[id]
	if !ok || value.TenantID != tenantID {
		return EvidenceReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) GetVEX(_ context.Context, tenantID, id string) (VEXReference, error) {
	value, ok := s.vex[id]
	if !ok || value.TenantID != tenantID {
		return VEXReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) GetControl(_ context.Context, tenantID, id string) (ControlReference, error) {
	value, ok := s.controls[id]
	if !ok || value.TenantID != tenantID {
		return ControlReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) ValidateSupportingReference(_ context.Context, tenantID, _, _ string, reference riskdomain.SupportingReference) error {
	if tenantID == "" || reference.ID == "" {
		return ErrNotFound
	}
	return nil
}
func (s *riskTestState) ResolveGovernanceSubject(_ context.Context, tenantID, subjectType, id string) (GovernanceSubjectReference, error) {
	if subjectType == "waiver" {
		waiver, ok := s.waivers[id]
		if ok && waiver.TenantID == tenantID {
			return GovernanceSubjectReference{Type: subjectType, ID: id, TenantID: tenantID}, nil
		}
	}
	value, ok := s.subjects[subjectType+"\x00"+id]
	if !ok || value.TenantID != tenantID {
		return GovernanceSubjectReference{}, ErrNotFound
	}
	return value, nil
}
func (s *riskTestState) ListVulnerabilityDecisions(_ context.Context, tenantID string) ([]riskdomain.VulnerabilityDecision, error) {
	result := []riskdomain.VulnerabilityDecision{}
	for _, value := range s.decisions {
		if value.TenantID == tenantID {
			result = append(result, cloneDecision(value))
		}
	}
	return result, nil
}
func (s *riskTestState) ListExceptions(_ context.Context, tenantID string) ([]riskdomain.Exception, error) {
	result := []riskdomain.Exception{}
	for _, value := range s.exceptions {
		if value.TenantID == tenantID {
			result = append(result, cloneException(value))
		}
	}
	return result, nil
}
func (s *riskTestState) SupersedeAndInsert(_ context.Context, decision riskdomain.VulnerabilityDecision, superseded []riskdomain.VulnerabilityDecision) error {
	for _, prior := range superseded {
		s.decisions[prior.ID] = cloneDecision(prior)
	}
	s.decisions[decision.ID] = cloneDecision(decision)
	return nil
}
func (s *riskTestState) InsertException(_ context.Context, exception riskdomain.Exception) error {
	s.exceptions[exception.ID] = cloneException(exception)
	return nil
}
func (s *riskTestState) GetExceptionForUpdate(_ context.Context, tenantID, id string) (riskdomain.Exception, error) {
	value, ok := s.exceptions[id]
	if !ok || value.TenantID != tenantID {
		return riskdomain.Exception{}, ErrNotFound
	}
	return cloneException(value), nil
}
func (s *riskTestState) ApproveException(_ context.Context, exception riskdomain.Exception) error {
	s.exceptions[exception.ID] = cloneException(exception)
	return nil
}
func (s *riskTestState) GetWaiverForUpdate(_ context.Context, tenantID, id string) (riskdomain.Waiver, error) {
	value, ok := s.waivers[id]
	if !ok || value.TenantID != tenantID {
		return riskdomain.Waiver{}, ErrNotFound
	}
	return cloneWaiver(value), nil
}
func (s *riskTestState) InsertWaiver(_ context.Context, waiver riskdomain.Waiver) error {
	if waiver.Supersedes != "" {
		previous, ok := s.waivers[waiver.Supersedes]
		if !ok || previous.TenantID != waiver.TenantID || previous.SupersededBy != "" {
			return ErrConflict
		}
		previous.SupersededBy = waiver.ID
		s.waivers[previous.ID] = previous
	}
	s.waivers[waiver.ID] = cloneWaiver(waiver)
	return nil
}
func (s *riskTestState) ApproveWaiver(_ context.Context, waiver riskdomain.Waiver) error {
	s.waivers[waiver.ID] = cloneWaiver(waiver)
	return nil
}
func (s *riskTestState) InsertApprovalRecord(_ context.Context, approval riskdomain.ApprovalRecord) error {
	s.approvals[approval.ID] = approval
	return nil
}
func (s *riskTestState) ReadReleaseReadinessSnapshot(_ context.Context, tenantID, releaseID string) (ReadinessSnapshot, error) {
	if s.readiness.TenantID != tenantID || s.readiness.ReleaseID != releaseID {
		return cloneReadinessSnapshot(s.readiness), nil
	}
	return cloneReadinessSnapshot(s.readiness), nil
}
func (s *riskTestState) InsertPolicyEvaluation(_ context.Context, evaluation riskdomain.PolicyEvaluation) error {
	s.evaluations[evaluation.ID] = clonePolicyEvaluation(evaluation)
	return nil
}
func (s *riskTestState) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if s.auditErr != nil {
		return application.AuditReceipt{}, s.auditErr
	}
	s.audit = append(s.audit, event)
	return application.AuditReceipt{ID: event.ID}, nil
}

type riskTestTransaction struct{ state *riskTestState }

func (t riskTestTransaction) Decisions() Repository                 { return t.state }
func (t riskTestTransaction) Governance() GovernanceRepository      { return t.state }
func (t riskTestTransaction) Authorization() application.Authorizer { return allowRiskAuthorizer{} }
func (t riskTestTransaction) Audit() application.AuditAppender      { return t.state }
