package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestEvidenceBundleAuthorizerRequiresMatchingResolvedReadGrants(t *testing.T) {
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "tenant", "bundle:read", true}, {"tenant", "other", "bundle:read", false}, {"product", "product", "bundle:read", true}, {"project", "project", "bundle:read", true}, {"release", "release", "bundle:read", true}, {"project", "other", "bundle:read", false}, {"release", "", "bundle:read", false}, {"product", "product", "bundle:write", false}, {"product", "product", "*", true}, {"build", "build", "bundle:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"bundle:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := NewEvidenceBundleAuthorizer().Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal(err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"bundle:read"}}
	for _, request := range []application.AuthorizationRequest{{Scope: "bundle:read", ScopeOnly: true, Resources: refs}, {Scope: "bundle:write", Resources: refs}, {Scope: "bundle:read", Resources: application.ResourceReferences{ProjectID: "project"}}, {Scope: "bundle:read", Resources: application.ResourceReferences{ArtifactID: "artifact"}}, {Scope: "bundle:read", TenantWide: true, Resources: refs}} {
		if err := NewEvidenceBundleAuthorizer().Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(err)
		}
	}
	if err := NewEvidenceBundleAuthorizer().Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "bundle:read", ScopeOnly: true}); err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // Deliberately prove the invalid-context guard fails closed.
	if err := NewEvidenceBundleAuthorizer().Authorize(nil, actor, application.AuthorizationRequest{Scope: "bundle:read"}); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := NewEvidenceBundleAuthorizer().Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
