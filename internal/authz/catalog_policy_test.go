package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var catalogCases = []struct {
	action    Action
	scope     string
	boundary  Boundary
	resources ResourceReferences
}{
	{ActionProductsRead, "product:read", ResourceBoundary, ResourceReferences{ProductID: "product"}},
	{ActionProductsCreate, "product:write", TenantBoundary, ResourceReferences{}},
	{ActionProjectsRead, "project:read", ResourceBoundary, ResourceReferences{ProductID: "product", ProjectID: "project"}},
	{ActionProjectsCreate, "project:write", ResourceBoundary, ResourceReferences{ProductID: "product"}},
	{ActionReleasesRead, "release:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{ActionReleasesManage, "release:write", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{ActionBuildsRead, "build:read", ResourceBoundary, ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}},
	{ActionBuildsCreate, "build:write", ResourceBoundary, ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}},
}

func TestCatalogPolicyIssuedActorsAndEffectiveCapabilities(t *testing.T) {
	for _, tc := range catalogCases {
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
					t.Fatalf("unrelated capability authorized: %v", err)
				}
				actor.Scopes = []string{tc.scope}
				refs := tc.resources
				refs.TenantID = "foreign"
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatalf("foreign tenant target authorized: %v", err)
				}
				refs.TenantID = "tenant"
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); err != nil {
					t.Fatalf("own tenant target denied: %v", err)
				}
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: tc.resources, Evaluation: Evaluation(255)}); !errors.Is(err, ErrForbidden) {
					t.Fatalf("unknown evaluation phase authorized: %v", err)
				}
			}
		})
	}
}

func TestCatalogPolicySSOResourceGrantsAndRevocation(t *testing.T) {
	for _, tc := range catalogCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{tc.scope}}
			request := Request{Action: tc.action, Resources: tc.resources}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("human without current grants authorized: %v", err)
			}
			for _, grantedScope := range []string{tc.scope, "admin", "*"} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{grantedScope}}}
				if err := Authorize(t.Context(), actor, request); err != nil {
					t.Fatalf("current tenant grant denied: %v", err)
				}
			}
			for _, grant := range []identitydomain.ResourceGrant{
				{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{tc.scope}},
				{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"unrelated"}},
				{ResourceType: "build", ResourceID: tc.resources.BuildID, Scopes: []string{tc.scope}},
			} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{grant}
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("inapplicable grant authorized: %v", err)
				}
			}
			for _, resource := range []struct{ kind, id string }{{"product", tc.resources.ProductID}, {"project", tc.resources.ProjectID}, {"release", tc.resources.ReleaseID}} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: resource.kind, ResourceID: resource.id, Scopes: []string{tc.scope}}}
				err := Authorize(t.Context(), actor, request)
				if resource.id != "" && err != nil || resource.id == "" && !errors.Is(err, ErrForbidden) {
					t.Fatalf("%s grant with coordinate %q: %v", resource.kind, resource.id, err)
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("unrelated %s grant authorized: %v", resource.kind, err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("revoked grant authorized: %v", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			actor.Scopes = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("resource grant bypassed issued capability: %v", err)
			}
		})
	}
}

func TestCatalogPolicyPreflightIsNotResourceOrTenantAuthority(t *testing.T) {
	for _, tc := range catalogCases {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{tc.scope}}
		preflight := Request{Action: tc.action, Evaluation: ScopeEvaluation}
		err := Authorize(t.Context(), actor, preflight)
		if tc.boundary == ResourceBoundary && err != nil || tc.boundary == TenantBoundary && !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s preflight = %v", tc.action, err)
		}
		inventory := Request{Action: tc.action, Evaluation: TenantEvaluation}
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{tc.scope}}}
		if err := Authorize(t.Context(), actor, inventory); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s product grant exposed tenant inventory: %v", tc.action, err)
		}
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
		if err := Authorize(t.Context(), actor, inventory); err != nil {
			t.Fatalf("%s current tenant inventory grant denied: %v", tc.action, err)
		}
		for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation} {
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode, Resources: ResourceReferences{ProductID: "product"}}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s phase %v silently discarded a resource: %v", tc.action, mode, err)
			}
		}
	}
	for _, tc := range actionCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("privileged action %s gained a scope-only bypass: %v", tc.action, err)
		}
	}
}

func TestCatalogPolicyRejectsIncompleteAndStrayCoordinates(t *testing.T) {
	for _, tc := range catalogCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		original := reflect.ValueOf(tc.resources)
		for i := 0; i < original.NumField(); i++ {
			field := original.Type().Field(i).Name
			if field == "TenantID" {
				continue
			}
			refs := tc.resources
			changed := reflect.ValueOf(&refs).Elem().Field(i)
			if original.Field(i).String() == "" {
				changed.SetString("stray")
			} else {
				if tc.action == ActionReleasesManage && field == "ReleaseID" {
					continue // The same write capability also creates a release under a product.
				}
				changed.SetString("")
			}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s accepted invalid %s coordinates: %#v error=%v", tc.action, field, refs, err)
			}
		}
	}
}
