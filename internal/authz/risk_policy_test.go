package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var riskCases = []struct {
	action           Action
	scope            string
	tenantEvaluation bool
}{
	{"vulnerability_decisions.record", "evidence:write", false},
	{"approvals.record", "release:write", true},
	{"waivers.manage", "policy:write", true},
	{"exceptions.manage", "release:write", false},
	{"vulnerability_workflows.record", "security:write", true},
	{"policy_evaluations.create", "verify:read", false},
	{"custom_policies.create", "policy:write", true},
	{"custom_policies.evaluate", "policy:read", false},
}

func TestRiskPolicyIssuedCapabilitiesAndCurrentHumanGrants(t *testing.T) {
	refs := ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}
	for _, tc := range riskCases {
		t.Run(string(tc.action), func(t *testing.T) {
			request := Request{Action: tc.action, Resources: refs}
			for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector", KeyID: "collector-key"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, request); err != nil {
						t.Fatalf("issued capability %q denied: %v", scope, err)
					}
				}
				actor.Scopes = []string{"unrelated", "instance:admin"}
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("unrelated scope allowed: %v", err)
				}
			}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{tc.scope}}
			for _, kind := range []string{"tenant", "product", "project", "release", "artifact"} {
				for _, scope := range []string{tc.scope, "admin", "*", "unrelated"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{scope}}}
					allow := kind != "artifact" && scope != "unrelated"
					err := Authorize(t.Context(), actor, request)
					if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
						t.Fatalf("%s grant scope %q allow=%v: %v", kind, scope, allow, err)
					}
				}
				actor.ResourceGrants[0].Scopes = []string{tc.scope}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("foreign grant allowed: %v", err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("revoked grant allowed: %v", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			actor.Scopes = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("grant bypassed issued scope: %v", err)
			}
		})
	}
}

func TestRiskPolicyExactCoordinatesAndEvaluationPhases(t *testing.T) {
	refs := ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}
	for _, tc := range riskCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
				t.Fatal("preflight", err)
			}
			err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation})
			if tc.tenantEvaluation && err != nil || !tc.tenantEvaluation && !errors.Is(err, ErrForbidden) {
				t.Fatalf("tenant evaluation allowed=%v: %v", tc.tenantEvaluation, err)
			}
			for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs, Evaluation: mode}); !errors.Is(err, ErrForbidden) {
					t.Fatalf("phase %v discarded coordinates: %v", mode, err)
				}
			}
			for i := 0; i < reflect.TypeOf(refs).NumField(); i++ {
				field := reflect.TypeOf(refs).Field(i).Name
				changed := refs
				value := reflect.ValueOf(&changed).Elem().Field(i)
				allow := false
				if value.String() == "" {
					value.SetString("foreign")
				} else {
					value.SetString("")
					allow = field == "ProjectID" || field == "ReleaseID"
				}
				err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: changed})
				if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
					t.Fatalf("coordinate %s allow=%v: %v", field, allow, err)
				}
			}
			actor = identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{tc.scope}}}}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("product grant promoted to tenant: %v", err)
			}
			actor.ResourceGrants[0].ResourceType, actor.ResourceGrants[0].ResourceID = "tenant", "tenant"
			err = Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation})
			if tc.tenantEvaluation && err != nil || !tc.tenantEvaluation && !errors.Is(err, ErrForbidden) {
				t.Fatalf("human tenant evaluation allowed=%v: %v", tc.tenantEvaluation, err)
			}
		})
	}
}
