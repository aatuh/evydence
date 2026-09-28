package app

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestCreateWaiverAuthorizesSubjectAndSupersedesAtomically(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}
	state.waivers["wv_old"] = riskdomain.Waiver{ID: "wv_old", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", Owner: "security", Risk: "medium", Reason: "old", ExpiresAt: now.Add(time.Hour), SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now.Add(-time.Hour)}
	authorizer := &recordingRiskAuthorizer{}
	service := newRiskTestService(t, state, authorizer, now)

	waiver, err := service.CreateWaiver(context.Background(), riskTestActor(), CreateWaiverInput{
		ScopeType: "release", ScopeID: "rel_1", Owner: "security", Risk: "low", Reason: "temporary", ExpiresAt: now.Add(2 * time.Hour), Supersedes: "wv_old",
	})
	if err != nil {
		t.Fatalf("create waiver: %v", err)
	}
	if waiver.ID != "wv_1" || waiver.Supersedes != "wv_old" || state.waivers["wv_old"].SupersededBy != waiver.ID {
		t.Fatalf("unexpected waiver state: new=%#v old=%#v", waiver, state.waivers["wv_old"])
	}
	if !authorizer.sawResource("policy:write", "prod_1", "rel_1") {
		t.Fatalf("resource authorization requests = %#v", authorizer.requests)
	}
}

func TestWaiverApprovalRollsBackWhenAuditFails(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}
	state.waivers["wv_1"] = riskdomain.Waiver{ID: "wv_1", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", Owner: "security", Risk: "low", Reason: "temporary", ExpiresAt: now.Add(time.Hour), SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now.Add(-time.Hour)}
	state.auditErr = errRiskTestFailure
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	_, err := service.ApproveWaiver(context.Background(), riskTestActor(), "wv_1")
	if !errors.Is(err, errRiskTestFailure) {
		t.Fatalf("approve error = %v", err)
	}
	if state.waivers["wv_1"].Approved {
		t.Fatalf("failed approval was published: %#v", state.waivers["wv_1"])
	}
}

func TestCreateApprovalValidatesTenantOwnedSubjectAndEvidence(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}
	state.evidence["ev_1"] = EvidenceReference{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.evidence["foreign"] = EvidenceReference{ID: "foreign", TenantID: "ten_2", ReleaseID: "rel_1"}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)

	approval, err := service.CreateApprovalRecord(context.Background(), riskTestActor(), CreateApprovalInput{SubjectType: "release", SubjectID: "rel_1", Decision: "approved", Reason: "reviewed", EvidenceID: "ev_1"})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if approval.ID != "apr_1" || approval.ApproverID != "usr_1" || state.approvals[approval.ID].EvidenceID != "ev_1" {
		t.Fatalf("unexpected approval: %#v", approval)
	}
	if _, err := service.CreateApprovalRecord(context.Background(), riskTestActor(), CreateApprovalInput{SubjectType: "release", SubjectID: "rel_1", Decision: "approved", Reason: "reviewed", EvidenceID: "foreign"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign evidence error = %v", err)
	}
}

func TestCreateWaiverValidatesLinkedControlPolicyAndSupersededWaiver(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}
	state.subjects["control\x00ctl_1"] = GovernanceSubjectReference{Type: "control", ID: "ctl_1", TenantID: "ten_1"}
	state.subjects["policy\x00pol_1"] = GovernanceSubjectReference{Type: "policy", ID: "pol_1", TenantID: "ten_1"}
	state.subjects["control\x00foreign"] = GovernanceSubjectReference{Type: "control", ID: "foreign", TenantID: "ten_2"}
	state.waivers["wv_old"] = riskdomain.Waiver{ID: "wv_old", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", ExpiresAt: now.Add(time.Hour)}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)
	base := CreateWaiverInput{ScopeType: "release", ScopeID: "rel_1", Owner: "security", Risk: "low", Reason: "temporary", ExpiresAt: now.Add(2 * time.Hour)}

	foreign := base
	foreign.ControlID = "foreign"
	if _, err := service.CreateWaiver(context.Background(), riskTestActor(), foreign); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign control error = %v", err)
	}
	missing := base
	missing.PolicyID = "missing"
	if _, err := service.CreateWaiver(context.Background(), riskTestActor(), missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy error = %v", err)
	}
	if len(state.waivers) != 1 || len(state.audit) != 0 {
		t.Fatalf("invalid links persisted: waivers=%#v audit=%#v", state.waivers, state.audit)
	}

	valid := base
	valid.ControlID, valid.PolicyID, valid.Supersedes = "ctl_1", "pol_1", "wv_old"
	waiver, err := service.CreateWaiver(context.Background(), riskTestActor(), valid)
	if err != nil || waiver.ControlID != "ctl_1" || waiver.PolicyID != "pol_1" || state.waivers["wv_old"].SupersededBy != waiver.ID {
		t.Fatalf("linked waiver = %#v, prior = %#v, error = %v", waiver, state.waivers["wv_old"], err)
	}
	if len(state.audit) != 1 || state.audit[0].EntryType != "waiver.created" {
		t.Fatalf("audit = %#v", state.audit)
	}
	if _, err := service.CreateWaiver(context.Background(), riskTestActor(), valid); !errors.Is(err, ErrConflict) {
		t.Fatalf("reusing superseded waiver error = %v", err)
	}
}

func TestApproveWaiverRejectsExpiredForeignAndUnknownSubjects(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1"}
	state.waivers["valid"] = riskdomain.Waiver{ID: "valid", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", ExpiresAt: now.Add(time.Hour)}
	state.waivers["expired"] = riskdomain.Waiver{ID: "expired", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", ExpiresAt: now}
	state.waivers["orphan"] = riskdomain.Waiver{ID: "orphan", TenantID: "ten_1", ScopeType: "release", ScopeID: "missing", ExpiresAt: now.Add(time.Hour)}
	state.waivers["foreign"] = riskdomain.Waiver{ID: "foreign", TenantID: "ten_2", ScopeType: "release", ScopeID: "rel_1", ExpiresAt: now.Add(time.Hour)}
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)
	for _, tt := range []struct {
		id   string
		want error
	}{{"expired", ErrConflict}, {"orphan", ErrNotFound}, {"foreign", ErrNotFound}} {
		if _, err := service.ApproveWaiver(context.Background(), riskTestActor(), tt.id); !errors.Is(err, tt.want) {
			t.Fatalf("approve %q error = %v, want %v", tt.id, err, tt.want)
		}
	}
	waiver, err := service.ApproveWaiver(context.Background(), riskTestActor(), "valid")
	if err != nil || !waiver.Approved || waiver.ApprovedBy != "usr_1" || waiver.ApprovedAt == nil {
		t.Fatalf("approved waiver = %#v, %v", waiver, err)
	}
	if _, err := service.ApproveWaiver(context.Background(), riskTestActor(), "valid"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate approval error = %v", err)
	}
	if len(state.audit) != 1 || state.audit[0].EntryType != "waiver.approved" {
		t.Fatalf("audit = %#v", state.audit)
	}
}

func TestCreateApprovalRollsBackWhenAuditFails(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := newRiskTestState()
	state.subjects["release\x00rel_1"] = GovernanceSubjectReference{Type: "release", ID: "rel_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.evidence["ev_1"] = EvidenceReference{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1"}
	state.auditErr = errRiskTestFailure
	service := newRiskTestService(t, state, allowRiskAuthorizer{}, now)
	_, err := service.CreateApprovalRecord(context.Background(), riskTestActor(), CreateApprovalInput{SubjectType: "release", SubjectID: "rel_1", Decision: "approved", Reason: "reviewed", EvidenceID: "ev_1"})
	if !errors.Is(err, errRiskTestFailure) || len(state.approvals) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed approval leaked state: error=%v approvals=%#v audit=%#v", err, state.approvals, state.audit)
	}
}

type recordingRiskAuthorizer struct {
	requests []application.AuthorizationRequest
}

func (a *recordingRiskAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	a.requests = append(a.requests, request)
	return nil
}

func (a *recordingRiskAuthorizer) sawResource(scope, productID, releaseID string) bool {
	for _, request := range a.requests {
		if request.Scope == scope && request.Resources.ProductID == productID && request.Resources.ReleaseID == releaseID && !request.ScopeOnly {
			return true
		}
	}
	return false
}
