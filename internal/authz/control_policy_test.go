package authz

import (
	"errors"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var controlCases = []struct {
	action   Action
	scope    string
	boundary Boundary
}{
	{"control_evidence.link", "controls:write", ResourceBoundary},
}

func TestControlLinkPolicyCurrentGrantsAndExplicitPhases(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"controls:write"}}
	request := Request{Action: "control_evidence.link", Resources: ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}}
	for _, kind := range []string{"tenant", "product", "project", "release", "artifact"} {
		for _, scope := range []string{"controls:write", "admin", "*", "controls:read"} {
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{scope}}}
			allow := kind != "artifact" && scope != "controls:read"
			err := Authorize(t.Context(), actor, request)
			if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s scope %s allowed=%v: %v", kind, scope, allow, err)
			}
		}
		actor.ResourceGrants[0].ResourceID = "foreign"
		actor.ResourceGrants[0].Scopes = []string{"controls:write"}
		if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
			t.Fatal("foreign grant", err)
		}
	}
	actor.ResourceGrants = nil
	if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked grant", err)
	}
	if err := Authorize(t.Context(), actor, Request{Action: request.Action, Evaluation: ScopeEvaluation}); err != nil {
		t.Fatal("preflight", err)
	}
	if err := Authorize(t.Context(), actor, Request{Action: request.Action, Evaluation: TenantEvaluation}); !errors.Is(err, ErrForbidden) {
		t.Fatal("ungranted tenant", err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:write"}}}
	if err := Authorize(t.Context(), actor, Request{Action: request.Action, Evaluation: TenantEvaluation}); err != nil {
		t.Fatal("current tenant", err)
	}
	for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation} {
		if err := Authorize(t.Context(), actor, Request{Action: request.Action, Resources: request.Resources, Evaluation: mode}); !errors.Is(err, ErrForbidden) {
			t.Fatal("discarded coordinates", err)
		}
	}
	actor.Scopes = nil
	if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
		t.Fatal("grant bypassed issued scope", err)
	}
}

func TestControlLinkPolicyIssuedCapabilitiesAndStrictShapes(t *testing.T) {
	for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
		for _, scope := range []string{"controls:write", "admin", "*"} {
			actor.Scopes = []string{scope}
			for _, refs := range []ResourceReferences{{}, {ProductID: "product"}, {ProductID: "product", ProjectID: "project", ReleaseID: "release"}, {ArtifactID: "artifact"}, {ArtifactID: "artifact", ProductID: "product", ReleaseID: "release"}} {
				if err := Authorize(t.Context(), actor, Request{Action: "control_evidence.link", Resources: refs}); err != nil {
					t.Fatalf("issued scope %q shape %#v: %v", scope, refs, err)
				}
			}
		}
		for _, refs := range []ResourceReferences{{TenantID: "foreign"}, {ProjectID: "project"}, {ReleaseID: "release"}, {ArtifactID: "artifact", ProjectID: "project"}, {ProductID: "product", BuildID: "build"}, {EnvironmentID: "environment"}, {CustomerPackageID: "package"}} {
			if err := Authorize(t.Context(), actor, Request{Action: "control_evidence.link", Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("unsupported shape %#v: %v", refs, err)
			}
		}
	}
}
