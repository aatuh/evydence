package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var artifactCases = []struct {
	action Action
	scope  string
}{
	{"artifacts.write", "evidence:write"},
	{"artifacts.read", "evidence:read"},
}

func TestArtifactReferenceActionsRequireCurrentHumanVisibility(t *testing.T) {
	for _, tc := range []struct {
		action Action
		scope  string
	}{
		{"artifacts.write", "evidence:write"},
		{ActionEvidenceWrite, "evidence:write"},
		{ActionSecurityEvidenceWrite, "security:write"},
		{ActionEvidenceDiffsCreate, "evidence:read"},
		{ActionVEXPreviewRead, "evidence:read"},
		{ActionBuildsCreate, "build:write"},
		{ActionBuildAttestationsCreate, "build:write"},
		{ActionReleaseCandidatesCreate, "release:write"},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso-session", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{
				{ResourceType: "project", ResourceID: "project", Scopes: []string{tc.scope}},
				{ResourceType: "product", ResourceID: "wrong-scope", Scopes: []string{"unrelated"}},
			}}
			request := Request{Action: tc.action, Resources: ResourceReferences{ArtifactID: "artifact"}}
			visible, calls := true, 0
			reader := ArtifactVisibilityFunc(func(_ context.Context, r ArtifactVisibilityRequest) (bool, error) {
				calls++
				if r.TenantID != "tenant" || r.ArtifactID != "artifact" || r.TenantWide || !reflect.DeepEqual(r.AllowedProjectIDs, []string{"project"}) || len(r.AllowedProductIDs)+len(r.AllowedReleaseIDs) != 0 {
					t.Fatalf("policy filters=%#v", r)
				}
				return visible, nil
			})
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("association-free human request authorized", err)
			}
			if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); err != nil || calls != 1 {
				t.Fatal("current human association denied", err, calls)
			}
			visible = false
			if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || calls != 2 {
				t.Fatal("missing association authorized", err, calls)
			}
			actor.ResourceGrants = nil
			if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) || calls != 2 {
				t.Fatal("revoked grant reached storage", err, calls)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			tenantReader := ArtifactVisibilityFunc(func(_ context.Context, r ArtifactVisibilityRequest) (bool, error) {
				calls++
				if !r.TenantWide || len(r.AllowedProductIDs)+len(r.AllowedProjectIDs)+len(r.AllowedReleaseIDs) != 0 {
					t.Fatalf("tenant authority retained narrow filters: %#v", r)
				}
				return false, nil
			})
			if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, tenantReader); !errors.Is(err, ErrForbidden) || calls != 3 {
				t.Fatal("tenant grant skipped current artifact existence", err, calls)
			}
			for _, refs := range []ResourceReferences{
				{TenantID: "foreign", ArtifactID: "artifact"},
				{ArtifactID: "artifact", ProductID: "product"},
				{ArtifactID: "artifact", ProjectID: "project"},
				{ArtifactID: "artifact", ReleaseID: "release"},
				{ArtifactID: "artifact", BuildID: "build"},
			} {
				request.Resources = refs
				if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, tenantReader); !errors.Is(err, ErrForbidden) || calls != 3 {
					t.Fatal("unresolved/foreign coordinates reached storage", refs, err, calls)
				}
			}
			request.Resources = ResourceReferences{TenantID: "tenant", ArtifactID: "artifact"}
			for _, actor := range []identitydomain.Actor{
				{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}},
				{TenantID: "tenant", CollectorID: "collector", Scopes: []string{tc.scope}},
			} {
				if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, tenantReader); err != nil || calls != 3 {
					t.Fatal("issued capability changed association lookup", err, calls)
				}
				actor.Scopes = []string{"instance:admin"}
				if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, tenantReader); !errors.Is(err, ErrForbidden) || calls != 3 {
					t.Fatal("instance capability crossed tenant action", err, calls)
				}
			}
		})
	}
}

func TestArtifactWriteActionHasNoUnresolvedAuthority(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	request := Request{Action: "artifacts.write", Evaluation: ScopeEvaluation}
	if err := Authorize(t.Context(), actor, request); err != nil {
		t.Fatal("artifact creation preflight", err)
	}
	for _, evaluation := range []Evaluation{ResolvedEvaluation, TenantEvaluation} {
		request.Evaluation = evaluation
		if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
			t.Fatal("empty artifact request promoted to resource authority", err)
		}
	}
}

func TestArtifactReferenceFailuresAndCancellationNeverConferAuthority(t *testing.T) {
	for _, action := range []Action{ActionArtifactsRead, ActionArtifactsWrite, ActionEvidenceWrite, ActionSecurityEvidenceWrite,
		ActionEvidenceDiffsCreate, ActionVEXPreviewRead, ActionBuildsCreate, ActionBuildAttestationsCreate, ActionReleaseCandidatesCreate} {
		t.Run(string(action), func(t *testing.T) {
			definition, _ := DefinitionFor(action)
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{definition.Scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{definition.Scope}}}}
			request := Request{Action: action, Resources: ResourceReferences{ArtifactID: "artifact"}}
			storageError := errors.New("association read failed")
			if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
				return true, storageError
			})); !errors.Is(err, storageError) {
				t.Fatal("storage error became authority or was hidden", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			if err := AuthorizeWithArtifactVisibility(ctx, actor, request, ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
				cancel()
				return true, nil
			})); !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation authorized", err)
			}
			if err := AuthorizeWithArtifactVisibility(ctx, actor, request, ArtifactVisibilityFunc(func(context.Context, ArtifactVisibilityRequest) (bool, error) {
				t.Fatal("canceled request reached storage")
				return true, nil
			})); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			var missing ArtifactVisibilityFunc
			for _, reader := range []ArtifactVisibilityReader{nil, missing} {
				if err := AuthorizeWithArtifactVisibility(t.Context(), actor, request, reader); !errors.Is(err, ErrForbidden) {
					t.Fatal("missing association proof authorized", err)
				}
			}
		})
	}
}
