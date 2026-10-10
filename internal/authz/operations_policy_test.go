package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var operationsCases = []struct {
	action           Action
	scope            string
	resources        ResourceReferences
	tenantEvaluation bool
}{
	{"environments.read", "deployment:read", ResourceReferences{ProductID: "product", EnvironmentID: "environment"}, true},
	{"environments.create", "deployment:write", ResourceReferences{ProductID: "product"}, false},
	{"deployments.read", "deployment:read", ResourceReferences{ProductID: "product", ReleaseID: "release", EnvironmentID: "environment", DeploymentID: "deployment"}, true},
	{"deployments.record", "deployment:write", ResourceReferences{ProductID: "product", ReleaseID: "release", EnvironmentID: "environment"}, false},
	{"incidents.manage", "incident:write", ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}, true},
}

func TestOperationsPolicyIssuedScopesAndTenantBoundary(t *testing.T) {
	for _, tc := range operationsCases {
		t.Run(string(tc.action), func(t *testing.T) {
			for _, actor := range []identitydomain.Actor{{KeyID: "key"}, {CollectorID: "collector", KeyID: "collector-key"}} {
				actor.TenantID = "tenant"
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: tc.resources}); err != nil {
						t.Fatalf("issued scope %q denied: %v", scope, err)
					}
				}
				actor.Scopes = []string{"instance:admin", "unrelated"}
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: tc.resources}); !errors.Is(err, ErrForbidden) {
					t.Fatalf("unrelated capability allowed: %v", err)
				}
				actor.Scopes = []string{tc.scope}
				refs := tc.resources
				refs.TenantID = "foreign"
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatalf("foreign tenant allowed: %v", err)
				}
				refs.TenantID = "tenant"
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); err != nil {
					t.Fatalf("own tenant denied: %v", err)
				}
			}
		})
	}
}

func TestOperationsPolicyCurrentSSOGrantsAndRevocation(t *testing.T) {
	for _, tc := range operationsCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{tc.scope}}
			request := Request{Action: tc.action, Resources: tc.resources}
			for _, resource := range []struct{ kind, id string }{
				{"tenant", "tenant"}, {"", ""}, {"product", tc.resources.ProductID},
				{"project", tc.resources.ProjectID}, {"release", tc.resources.ReleaseID},
				{"environment", tc.resources.EnvironmentID}, {"deployment", tc.resources.DeploymentID}, {"build", tc.resources.BuildID},
			} {
				for _, scope := range []string{tc.scope, "admin", "*", "unrelated"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: resource.kind, ResourceID: resource.id, Scopes: []string{scope}}}
					allow := scope != "unrelated" && (resource.kind == "tenant" || resource.kind == "" || resource.id != "" && (resource.kind == "product" || resource.kind == "project" || resource.kind == "release"))
					err := Authorize(t.Context(), actor, request)
					if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
						t.Fatalf("%s grant %q scope %q allow=%v: %v", resource.kind, resource.id, scope, allow, err)
					}
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				actor.ResourceGrants[0].Scopes = []string{tc.scope}
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
				t.Fatalf("grant bypassed issued capability: %v", err)
			}
		})
	}
}

func TestOperationsPolicyEvaluationPhasesDoNotDiscardCoordinates(t *testing.T) {
	for _, tc := range operationsCases {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{tc.scope}}
		if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
			t.Fatalf("%s preflight denied: %v", tc.action, err)
		}
		if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s grantless tenant operation allowed: %v", tc.action, err)
		}
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
		err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation})
		if tc.tenantEvaluation && err != nil || !tc.tenantEvaluation && !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s tenant evaluation allowed=%v: %v", tc.action, tc.tenantEvaluation, err)
		}
		for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode, Resources: tc.resources}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s phase %v discarded resolved coordinates: %v", tc.action, mode, err)
			}
		}
	}
}

func TestOperationsPolicyExactResolvedShapes(t *testing.T) {
	for _, tc := range operationsCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		original := reflect.ValueOf(tc.resources)
		for i := 0; i < original.NumField(); i++ {
			name := original.Type().Field(i).Name
			if name == "TenantID" {
				continue
			}
			refs := tc.resources
			changed := reflect.ValueOf(&refs).Elem().Field(i)
			if original.Field(i).String() == "" {
				changed.SetString("stray")
			} else {
				changed.SetString("")
			}
			optional := tc.action == "incidents.manage" && name != "ProductID" && original.Field(i).String() != ""
			err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs})
			if optional && err != nil || !optional && !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s coordinate %s optional=%v refs=%#v: %v", tc.action, name, optional, refs, err)
			}
		}
	}
}
