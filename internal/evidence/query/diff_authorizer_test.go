package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestDiffAuthorizerUsesEvidenceReadGrantsAndArtifactPolicy(t *testing.T) {
	artifacts := &creationArtifactAuthorizerFake{}
	auth, err := NewDiffAuthorizer(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:read"}}}}
	r := application.AuthorizationRequest{Scope: "evidence:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	if err := auth.Authorize(t.Context(), a, r); err != nil || artifacts.calls != 0 {
		t.Fatal(err)
	}
	r.Resources.ReleaseID = "other"
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong release grant accepted", err)
	}
	a.ResourceGrants = nil
	r.ScopeOnly = true
	r.Resources = application.ResourceReferences{}
	if err := auth.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("scope-only metadata check denied", err)
	}
	r.ScopeOnly = false
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("detached human read without tenant grant", err)
	}
	r.Resources.ArtifactID = "artifact"
	artifacts.err = application.ErrForbidden
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) || artifacts.calls != 1 {
		t.Fatal("artifact grant not checked", err)
	}
	for _, bad := range []application.AuthorizationRequest{{Scope: "evidence:write"}, {Scope: "evidence:read", TenantWide: true}, {Scope: "evidence:read", ScopeOnly: true, Resources: application.ResourceReferences{ProductID: "product"}}, {Scope: "evidence:read", Resources: application.ResourceReferences{ArtifactID: "artifact", ReleaseID: "release"}}, {Scope: "evidence:read", Resources: application.ResourceReferences{BuildID: "build"}}} {
		if err := auth.Authorize(t.Context(), a, bad); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("invalid auth request accepted", bad, err)
		}
	}
	a.KeyID = "key"
	r.Resources = application.ResourceReferences{ProductID: "product"}
	if err := auth.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("scoped key denied", err)
	}
	a.KeyID = ""
	a.UserID = ""
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := auth.Authorize(ctx, a, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := NewDiffAuthorizer(nil); err == nil {
		t.Fatal("nil artifact policy accepted")
	}
}
