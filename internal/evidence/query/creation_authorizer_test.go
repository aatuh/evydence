package query

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type creationScopeFake struct {
	resolved application.ResourceReferences
	err      error
	tenant   string
	request  application.ResourceReferences
	calls    int
}

func (r *creationScopeFake) ResolveEvidenceCreationScope(_ context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	r.tenant, r.request = tenant, refs
	r.calls++
	return r.resolved, r.err
}

type creationArtifactAuthorizerFake struct {
	calls   int
	request application.AuthorizationRequest
	err     error
}

func TestSecurityDocumentAuthorizerKeepsSecurityScopeAndCurrentParents(t *testing.T) {
	reader := &creationScopeFake{resolved: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	artifacts := &creationArtifactAuthorizerFake{}
	auth, err := NewSecurityDocumentAuthorizer(reader, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"security:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"security:write"}}}}
	r := application.AuthorizationRequest{Scope: "security:write", Resources: application.ResourceReferences{ReleaseID: "release"}}
	if err := auth.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	a.ResourceGrants[0].Scopes = []string{"evidence:write"}
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong grant scope accepted", err)
	}
	a.ResourceGrants[0].Scopes = []string{"security:write"}
	reader.err = ErrNotFound
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing current parent accepted", err)
	}
	reader.err = nil
	r.Resources = application.ResourceReferences{ArtifactID: "artifact"}
	if err := auth.Authorize(t.Context(), a, r); err != nil || artifacts.request.Scope != "security:write" {
		t.Fatal("artifact scope changed", err)
	}
	for _, scope := range []string{"evidence:write", "admin", "security:read"} {
		r.Scope = scope
		if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unrelated scope accepted", scope, err)
		}
	}
}

func (a *creationArtifactAuthorizerFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	a.calls++
	a.request = r
	return a.err
}

func TestEvidenceCreationAuthorizerUsesOnlyCurrentCoherentParents(t *testing.T) {
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}
	reader := &creationScopeFake{resolved: refs}
	artifacts := &creationArtifactAuthorizerFake{}
	auth, err := NewEvidenceCreationAuthorizer(reader, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	r := application.AuthorizationRequest{Scope: "evidence:write", Resources: application.ResourceReferences{BuildID: "build"}}
	if err := auth.Authorize(t.Context(), actor, r); err != nil {
		t.Fatal(err)
	}
	if reader.tenant != actor.TenantID || reader.request != r.Resources || artifacts.calls != 0 {
		t.Fatal(reader, artifacts)
	}
	actor.ResourceGrants[0].ResourceID = "old-project"
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("stale grant accepted", err)
	}
	actor.KeyID = "key"
	if err := auth.Authorize(t.Context(), actor, r); err != nil {
		t.Fatal("scoped key denied", err)
	}
	reader.err = ErrNotFound
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, ErrNotFound) {
		t.Fatal("key bypassed ownership", err)
	}
	reader.err = nil
	for _, bad := range []application.ResourceReferences{
		{BuildID: "other", ProductID: "product", ProjectID: "project", ReleaseID: "release"},
		{BuildID: "build", ProjectID: "project", ReleaseID: "release"},
		{BuildID: "build", ProductID: "product", ReleaseID: "release"},
		{BuildID: "build", ProductID: "product", ProjectID: "project"},
		{BuildID: "build", ProductID: "product", ProjectID: "project", ReleaseID: "release", ArtifactID: "artifact"},
	} {
		reader.resolved = bad
		if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, ErrConflict) {
			t.Fatal("invalid resolution accepted", bad, err)
		}
	}
}

func TestEvidenceCreationAuthorizerRejectsInvalidRequestsBeforeReads(t *testing.T) {
	reader := &creationScopeFake{}
	artifacts := &creationArtifactAuthorizerFake{}
	auth, _ := NewEvidenceCreationAuthorizer(reader, artifacts)
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	for _, r := range []application.AuthorizationRequest{
		{Scope: "security:write"},
		{Scope: "evidence:write", TenantWide: true},
		{Scope: "evidence:write", ScopeOnly: true, Resources: application.ResourceReferences{BuildID: "build"}},
		{Scope: "evidence:write", Resources: application.ResourceReferences{EnvironmentID: "environment"}},
		{Scope: "evidence:write", Resources: application.ResourceReferences{ArtifactID: "artifact", ProductID: "product"}},
	} {
		if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(r, err)
		}
	}
	for _, id := range []string{"\x00bad", strings.Repeat("x", 1025), " project ", string([]byte{255})} {
		if err := auth.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "evidence:write", Resources: application.ResourceReferences{ProjectID: id}}); !errors.Is(err, ErrValidation) {
			t.Fatal(id, err)
		}
	}
	if err := auth.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "evidence:write", ScopeOnly: true}); err != nil {
		t.Fatal(err)
	}
	if reader.calls != 0 || artifacts.calls != 0 {
		t.Fatal("invalid/scope-only request read data", reader, artifacts)
	}
	unauthenticated := actor
	unauthenticated.KeyID = ""
	if err := auth.Authorize(t.Context(), unauthenticated, application.AuthorizationRequest{Scope: "evidence:write"}); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("missing identity accepted", err)
	}
	unscoped := actor
	unscoped.Scopes = nil
	if err := auth.Authorize(t.Context(), unscoped, application.AuthorizationRequest{Scope: "evidence:write"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("missing scope accepted", err)
	}
	if reader.calls != 0 || artifacts.calls != 0 {
		t.Fatal("unauthorized request read data")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := auth.Authorize(cancelled, actor, application.AuthorizationRequest{Scope: "evidence:write"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var nilContext context.Context
	if err := auth.Authorize(nilContext, actor, application.AuthorizationRequest{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := NewEvidenceCreationAuthorizer(nil, artifacts); err == nil {
		t.Fatal("nil scope reader accepted")
	}
	if _, err := NewEvidenceCreationAuthorizer(reader, nil); err == nil {
		t.Fatal("nil artifact policy accepted")
	}
}

func TestEvidenceCreationAuthorizerDetachedAndArtifactPolicy(t *testing.T) {
	reader := &creationScopeFake{}
	artifacts := &creationArtifactAuthorizerFake{}
	auth, _ := NewEvidenceCreationAuthorizer(reader, artifacts)
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}}
	r := application.AuthorizationRequest{Scope: "evidence:write"}
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("detached evidence needs tenant grant", err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"evidence:write"}}}
	if err := auth.Authorize(t.Context(), actor, r); err != nil {
		t.Fatal(err)
	}
	reader.resolved = application.ResourceReferences{ProductID: "invented"}
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, ErrConflict) {
		t.Fatal("invented parent accepted", err)
	}
	reads := reader.calls
	r.Resources = application.ResourceReferences{ArtifactID: "artifact"}
	artifacts.err = application.ErrForbidden
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if reader.calls != reads || artifacts.calls != 1 || artifacts.request != r {
		t.Fatal("artifact policy not delegated narrowly", reader, artifacts)
	}
}
