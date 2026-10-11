package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestReleaseReadVisibilityPreservesActionSpecificGrantHierarchies(t *testing.T) {
	for _, tc := range []struct {
		action             Action
		scope              string
		projects, releases bool
	}{
		{ActionProductsRead, "product:read", false, false},
		{"release_candidates.read", "release:read", false, true},
		{"artifacts.read", "evidence:read", true, true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{
				{ResourceType: "product", ResourceID: "product-b", Scopes: []string{tc.scope}},
				{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"admin"}},
				{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"*"}},
				{ResourceType: "project", ResourceID: "project", Scopes: []string{tc.scope}},
				{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}},
				{ResourceType: "product", ResourceID: "wrong-scope", Scopes: []string{"unrelated"}},
				{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
				{ResourceType: "build", ResourceID: "build", Scopes: []string{tc.scope}},
			}}
			visibility, err := ReadVisibility(t.Context(), actor, tc.action)
			want := Visibility{TenantID: "tenant", ProductIDs: []string{"product-a", "product-b"}}
			if tc.projects {
				want.ProjectIDs = []string{"project"}
			}
			if tc.releases {
				want.ReleaseIDs = []string{"release"}
			}
			if err != nil || !reflect.DeepEqual(visibility, want) {
				t.Fatal("action-specific current filters", visibility, want, err)
			}
			actor.ResourceGrants = nil
			visibility, err = ReadVisibility(t.Context(), actor, tc.action)
			if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant"}) {
				t.Fatal("revoked visibility retained authority", visibility, err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			visibility, err = ReadVisibility(t.Context(), actor, tc.action)
			if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant", TenantWide: true}) {
				t.Fatal("tenant visibility", visibility, err)
			}
			for _, actor := range []identitydomain.Actor{
				{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}},
				{TenantID: "tenant", CollectorID: "collector", Scopes: []string{tc.scope}},
			} {
				visibility, err = ReadVisibility(t.Context(), actor, tc.action)
				if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant", TenantWide: true}) {
					t.Fatal("issued capability", visibility, err)
				}
				actor.Scopes = []string{"instance:admin"}
				if visibility, err = ReadVisibility(t.Context(), actor, tc.action); !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
					t.Fatal("instance authority crossed tenant read", visibility, err)
				}
			}
		})
	}
}

func TestArtifactReadPolicyNeedsAssociationForScopedHumanButNotTenantAuthority(t *testing.T) {
	request := Request{Action: "artifacts.read", Resources: ResourceReferences{ArtifactID: "artifact"}}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:read"}}}}
	if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
		t.Fatal("association-free scoped artifact read", err)
	}
	visible, calls := false, 0
	reader := ArtifactVisibilityFunc(func(_ context.Context, r ArtifactVisibilityRequest) (bool, error) {
		calls++
		if r.TenantID != "tenant" || r.ArtifactID != "artifact" || r.TenantWide || !reflect.DeepEqual(r.AllowedProjectIDs, []string{"project"}) {
			t.Fatal("read proof filters", r)
		}
		return visible, nil
	})
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || calls != 1 {
		t.Fatal("invisible read", err, calls)
	}
	visible = true
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); err != nil || calls != 2 {
		t.Fatal("visible read", err, calls)
	}
	actor.ResourceGrants = nil
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || calls != 2 {
		t.Fatal("revocation reached proof reader", err, calls)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"evidence:read"}}}
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); err != nil || calls != 2 {
		t.Fatal("tenant point-read authority changed", err, calls)
	}
	for _, refs := range []ResourceReferences{{ArtifactID: "artifact", ProductID: "product"}, {ArtifactID: "artifact", ReleaseID: "release"}, {TenantID: "foreign", ArtifactID: "artifact"}, {}} {
		request.Resources = refs
		if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || calls != 2 {
			t.Fatal("unsupported read reference authorized", refs, err, calls)
		}
	}
	request.Resources = ResourceReferences{ArtifactID: "artifact"}
	for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
		for _, scope := range []string{"evidence:read", "admin", "*"} {
			actor.Scopes = []string{scope}
			if err := Authorize(t.Context(), actor, request); err != nil {
				t.Fatal("issued artifact read capability denied", scope, err)
			}
		}
		actor.Scopes = []string{"instance:admin"}
		if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
			t.Fatal("instance authority minted artifact read", err)
		}
	}
}

func TestReleaseReadVisibilityDoesNotNormalizeGrantIdentityIntoAuthority(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"product:read", "release:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: " padded-product ", Scopes: []string{"product:read", "release:read"}},
		{ResourceType: "product", ResourceID: " ", Scopes: []string{"product:read", "release:read"}},
		{ResourceType: "release", ResourceID: " ", Scopes: []string{"release:read"}},
	}}
	products, err := ReadVisibility(t.Context(), actor, ActionProductsRead)
	if err != nil || products.TenantWide || len(products.ProductIDs) != 0 || len(products.ProjectIDs)+len(products.ReleaseIDs) != 0 {
		t.Fatal("padded product grant became normalized point authority", products, err)
	}
	candidates, err := ReadVisibility(t.Context(), actor, ActionReleaseCandidatesRead)
	if err != nil || candidates.TenantWide || !reflect.DeepEqual(candidates.ProductIDs, []string{" padded-product "}) || len(candidates.ReleaseIDs) != 0 {
		t.Fatal("candidate filters normalized identity or retained blank claims", candidates, err)
	}
}
