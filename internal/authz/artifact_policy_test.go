package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestArtifactPolicyRequiresCurrentAssociationEvenForMatchingFilterGrant(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:write"}},
		{ResourceType: "project", ResourceID: "project-b", Scopes: []string{"controls:write"}},
		{ResourceType: "project", ResourceID: "project-a", Scopes: []string{"admin"}},
		{ResourceType: "project", ResourceID: "project-a", Scopes: []string{"*"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"controls:write"}},
		{ResourceType: "release", ResourceID: "unrelated", Scopes: []string{"controls:read"}},
		{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
	}}
	request := Request{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact", ProductID: "product", ReleaseID: "release"}}
	if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
		t.Fatal("filter coordinates substituted for association proof", err)
	}
	var requests []ArtifactVisibilityRequest
	visible := false
	reader := ArtifactVisibilityFunc(func(_ context.Context, r ArtifactVisibilityRequest) (bool, error) {
		requests = append(requests, r)
		return visible, nil
	})
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) {
		t.Fatal("invisible association authorized", err)
	}
	want := ArtifactVisibilityRequest{TenantID: "tenant", ArtifactID: "artifact", ProductID: "product", ReleaseID: "release", AllowedProductIDs: []string{"product"}, AllowedProjectIDs: []string{"project-a", "project-b"}, AllowedReleaseIDs: []string{"release"}}
	if !reflect.DeepEqual(requests, []ArtifactVisibilityRequest{want}) {
		t.Fatalf("association filters=%#v, want=%#v", requests, want)
	}
	visible = true
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); err != nil || len(requests) != 2 {
		t.Fatal("current association denied", err, requests)
	}
	actor.ResourceGrants = nil
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || len(requests) != 2 {
		t.Fatal("revoked grant reached association reader", err, requests)
	}
}

func TestArtifactPolicyDeniedShapesScopesAndOtherActionsNeverReadAssociations(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:write"}}}}
	reader := ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
		t.Fatal("denied request reached association reader")
		return true, nil
	})
	for _, request := range []Request{
		{Action: ActionOutboxReplay}, {Action: ActionProductsRead, Resources: ResourceReferences{ProductID: "product"}},
		{Action: ActionControlEvidenceLink, Resources: ResourceReferences{TenantID: "foreign", ArtifactID: "artifact"}},
		{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact", ProjectID: "project"}},
		{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact"}, Evaluation: ScopeEvaluation},
		{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact"}, Evaluation: TenantEvaluation},
	} {
		if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) {
			t.Fatalf("unsupported request %#v: %v", request, err)
		}
	}
	actor.Scopes = []string{"controls:read"}
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, Request{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact"}}, reader); !errors.Is(err, ErrForbidden) {
		t.Fatal("wrong issued scope", err)
	}
}

func TestArtifactPolicyTenantAuthorityDoesNotRequireNarrowAssociationGrants(t *testing.T) {
	reader := ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
		t.Fatal("tenant authority reached narrow association reader")
		return false, nil
	})
	request := Request{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact", ProductID: "product", ReleaseID: "release"}}
	for _, actor := range []identitydomain.Actor{
		{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:write"}},
		{TenantID: "tenant", CollectorID: "collector", Scopes: []string{"controls:write"}},
		{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:write"}}}},
	} {
		if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); err != nil {
			t.Fatal("existing tenant capability denied", err)
		}
	}
}

func TestArtifactPolicyPropagatesStorageFailureAndCancellation(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"controls:write"}}}}
	request := Request{Action: ActionControlEvidenceLink, Resources: ResourceReferences{ArtifactID: "artifact"}}
	storageError := errors.New("association storage failed")
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) { return true, storageError })); !errors.Is(err, storageError) {
		t.Fatal("storage failure hidden", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader := ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) { cancel(); return true, nil })
	if err := AuthorizeWithArtifactVisibility(ctx, actor, request, reader); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation authorized", err)
	}
	if err := AuthorizeWithArtifactVisibility(ctx, actor, request, ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
		t.Fatal("canceled policy reached reader")
		return true, nil
	})); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var missing ArtifactVisibilityFunc
	if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, missing); !errors.Is(err, ErrForbidden) {
		t.Fatal("nil visibility function did not fail closed", err)
	}
}
