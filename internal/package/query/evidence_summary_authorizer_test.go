package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSummaryAuthorizerRequiresCurrentMatchingGrants(t *testing.T) {
	policy := NewEvidenceSummaryAuthorizer()
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", CustomerPackageID: "package"}
	for _, kind := range []string{"tenant", "product", "project", "release", "customer_security_package"} {
		t.Run(kind, func(t *testing.T) {
			id := map[string]string{"tenant": "tenant", "product": "product", "project": "project", "release": "release", "customer_security_package": "package"}[kind]
			a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: id, Scopes: []string{"report:read"}}}}
			r := application.AuthorizationRequest{Scope: "report:read", Resources: refs}
			if err := policy.Authorize(t.Context(), a, r); err != nil {
				t.Fatal(err)
			}
			a.ResourceGrants[0].ResourceID = "other"
			if err := policy.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("foreign grant accepted", err)
			}
			a.ResourceGrants = nil
			if err := policy.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant accepted", err)
			}
		})
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"report:read"}}
	if err := policy.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "report:read", ScopeOnly: true}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []application.AuthorizationRequest{{Scope: "other", Resources: refs}, {Scope: "report:read", ScopeOnly: true, Resources: refs}, {Scope: "report:read", TenantWide: true, Resources: refs}, {Scope: "report:read", Resources: application.ResourceReferences{ArtifactID: "artifact"}}, {Scope: "report:read", Resources: application.ResourceReferences{ReleaseID: "release"}}} {
		if err := policy.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("invalid authority coordinates", r, err)
		}
	}
	a.KeyID = ""
	a.UserID = "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"report:read"}}}
	if err := policy.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "report:read", TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product grant permits tenant summary", err)
	}
	a.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"report:read"}}
	if err := policy.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "report:read", TenantWide: true}); err != nil {
		t.Fatal(err)
	}
}
