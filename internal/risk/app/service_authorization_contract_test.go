package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type genericRiskPolicy struct {
	t          *testing.T
	want, seen []application.AuthorizationRequest
}

func (p *genericRiskPolicy) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	p.seen = append(p.seen, r)
	i := len(p.seen) - 1
	if i >= len(p.want) || r != p.want[i] {
		p.t.Errorf("authorization step %d has wrong action/coordinates: %#v", i, r)
		return application.ErrForbidden
	}
	mode := authz.ResolvedEvaluation
	if r.ScopeOnly {
		mode = authz.ScopeEvaluation
	}
	if r.TenantWide {
		mode = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, a, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: mode})
}

func TestGenericRiskDecisionExceptionAndReportMethodsBindDistinctTypedActions(t *testing.T) {
	for _, operation := range []string{"decision-create", "decisions-list", "summary", "exception-create", "exceptions-list", "exception-approve"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
			s := newRiskTestState()
			s.products["product"] = ProductReference{ID: "product", TenantID: "tenant"}
			s.releases["release"] = ReleaseReference{ID: "release", TenantID: "tenant", ProductID: "product"}
			s.findings["finding"] = FindingReference{ID: "finding", TenantID: "tenant", ScanID: "scan", ProductID: "product", ReleaseID: "release", Vulnerability: "CVE-2026-0001", Component: "pkg"}
			status, _ := riskdomain.ParseDecisionStatus("fixed")
			s.decisions["old"] = riskdomain.VulnerabilityDecision{ID: "old", TenantID: "tenant", ReleaseID: "release", FindingID: "finding", Status: status, CustomerVisible: true, CreatedAt: now}
			s.exceptions["exception"] = riskdomain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "release", ExpiresAt: now.Add(time.Hour)}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
			refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
			action := authz.ActionVulnerabilityDecisionsRecord
			switch operation {
			case "decisions-list":
				action = authz.ActionVulnerabilityDecisionsRead
			case "summary":
				action = authz.ActionVulnerabilityDecisionSummaryRead
			case "exception-create", "exception-approve":
				action = authz.ActionExceptionsManage
			case "exceptions-list":
				action = authz.ActionExceptionsRead
			}
			preflight := application.AuthorizationRequest{Action: action, ScopeOnly: true}
			resolved := application.AuthorizationRequest{Action: action, Resources: refs}
			want := []application.AuthorizationRequest{preflight, resolved}
			if operation == "decision-create" || operation == "exception-create" || operation == "exceptions-list" {
				want = append(want, resolved)
			}
			if operation == "decisions-list" {
				want = []application.AuthorizationRequest{preflight, {Action: action, Resources: application.ResourceReferences{ProductID: "product"}}, resolved, resolved}
			}
			policy := &genericRiskPolicy{t: t, want: want}
			s.policy = policy
			service := newRiskTestService(t, s, policy, now)
			var err error
			switch operation {
			case "decision-create":
				got, runErr := service.CreateVulnerabilityDecision(t.Context(), a, "finding", CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "patched"})
				err = runErr
				if got.ID == "" || s.decisions[got.ID].ID != got.ID || len(s.audit) != 2 {
					t.Error("decision lost atomic creation/supersession")
				}
			case "decisions-list":
				got, runErr := service.ListVulnerabilityDecisions(t.Context(), a, ListVulnerabilityDecisionsInput{ProductID: "product", ReleaseID: "release"})
				err = runErr
				if len(got) != 1 || got[0].ID != "old" {
					t.Error("decision selection changed")
				}
			case "summary":
				got, runErr := service.VulnerabilityDecisionSummaryReport(t.Context(), a, "release")
				err = runErr
				if got.ReleaseID != "release" || len(got.Decisions) != 1 {
					t.Error("customer summary selection changed")
				}
			case "exception-create":
				got, runErr := service.CreateException(t.Context(), a, CreateExceptionInput{ReleaseID: "release", Reason: "reason", Owner: "owner", ExpiresAt: now.Add(time.Hour)})
				err = runErr
				if got.ID == "" || s.exceptions[got.ID].ID != got.ID || len(s.audit) != 1 {
					t.Error("exception lost atomic creation/audit")
				}
			case "exceptions-list":
				got, runErr := service.ListExceptions(t.Context(), a, "release")
				err = runErr
				if len(got) != 1 || got[0].ID != "exception" {
					t.Error("exception selection changed")
				}
			case "exception-approve":
				got, runErr := service.ApproveException(t.Context(), a, "exception")
				err = runErr
				if !got.Approved || !s.exceptions["exception"].Approved || len(s.audit) != 1 {
					t.Error("exception approval lost atomic audit")
				}
			}
			if err != nil || !reflect.DeepEqual(policy.seen, policy.want) {
				t.Fatal("generic Risk method lost its typed policy sequence", err)
			}
		})
	}
}

func TestGenericReadinessUsesDistinctReadAndPersistenceActions(t *testing.T) {
	for _, persist := range []bool{false, true} {
		s := newRiskTestState()
		s.readiness = passingReadinessSnapshot()
		action := authz.ActionReleaseReadinessRead
		if persist {
			action = authz.ActionPolicyEvaluationsCreate
		}
		request := application.AuthorizationRequest{Action: action, Resources: application.ResourceReferences{ProductID: s.readiness.ProductID, ReleaseID: s.readiness.ReleaseID}}
		want := []application.AuthorizationRequest{{Action: action, ScopeOnly: true}, request}
		if persist {
			want = append(want, request)
		}
		policy := &genericRiskPolicy{t: t, want: want}
		s.policy = policy
		now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
		service := newRiskTestService(t, s, policy, now)
		actor := identitydomain.Actor{TenantID: s.readiness.TenantID, KeyID: "key", Scopes: []string{"verify:read"}}
		var result riskdomain.PolicyEvaluation
		var err error
		if persist {
			result, err = service.EvaluateRelease(t.Context(), actor, s.readiness.ReleaseID)
		} else {
			result, err = service.PreviewReleaseReadiness(t.Context(), actor, s.readiness.ReleaseID)
		}
		if err != nil || result.Result != "passed" || !reflect.DeepEqual(policy.seen, policy.want) {
			t.Fatal("readiness borrowed the other workflow's action", persist, err)
		}
		if persist && (result.ID == "" || len(s.evaluations) != 1 || len(s.audit) != 1) || !persist && (result.ID != "" || len(s.evaluations)+len(s.audit)+s.executeCalls != 0) {
			t.Fatal("readiness changed read-only/persisted effects", persist)
		}
	}
}

func TestGenericGovernancePreservesScopedReleaseAndTenantControlAuthority(t *testing.T) {
	for _, kind := range []string{"release", "control"} {
		for _, operation := range []string{"waiver-create", "waiver-approve", "approval"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				s := newRiskTestState()
				now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
				subject := GovernanceSubjectReference{Type: kind, ID: "subject", TenantID: "tenant"}
				if kind == "release" {
					subject.ProductID, subject.ReleaseID = "product", "subject"
				}
				s.subjects[kind+"\x00subject"] = subject
				s.waivers["waiver"] = riskdomain.Waiver{ID: "waiver", TenantID: "tenant", ScopeType: kind, ScopeID: "subject", ExpiresAt: now.Add(time.Hour)}
				action, scope := authz.ActionWaiversManage, "policy:write"
				if operation == "approval" {
					action, scope = authz.ActionApprovalsRecord, "release:write"
				}
				resolved := application.AuthorizationRequest{Action: action, Resources: subjectResources(subject), TenantWide: kind == "control"}
				want := []application.AuthorizationRequest{{Action: action, ScopeOnly: true}, resolved}
				if operation != "waiver-approve" {
					want = append(want, resolved)
				}
				policy := &genericRiskPolicy{t: t, want: want}
				if kind == "control" && operation == "approval" {
					policy.want = policy.want[:1]
				}
				s.policy = policy
				service := newRiskTestService(t, s, policy, now)
				grant := identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "product", Scopes: []string{scope}}
				if kind == "control" {
					grant.ResourceType, grant.ResourceID = "tenant", "tenant"
				}
				actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{scope}, ResourceGrants: []identitydomain.ResourceGrant{grant}}
				var err error
				switch operation {
				case "waiver-create":
					_, err = service.CreateWaiver(t.Context(), actor, CreateWaiverInput{ScopeType: kind, ScopeID: "subject", Owner: "owner", Risk: "low", Reason: "reason", ExpiresAt: now.Add(time.Hour)})
				case "waiver-approve":
					_, err = service.ApproveWaiver(t.Context(), actor, "waiver")
				case "approval":
					_, err = service.CreateApprovalRecord(t.Context(), actor, CreateApprovalInput{SubjectType: kind, SubjectID: "subject", Decision: "approved", Reason: "reviewed"})
				}
				if kind == "control" && operation == "approval" {
					if !errors.Is(err, ErrValidation) || len(s.audit)+len(s.approvals) != 0 || !reflect.DeepEqual(policy.seen, policy.want) {
						t.Fatal("unsupported control approval bypassed its input contract", err)
					}
				} else if err != nil || len(s.audit) != 1 || !reflect.DeepEqual(policy.seen, policy.want) {
					t.Fatal("governance lost distinct resource/tenant policy", err)
				}
			})
		}
	}
}
