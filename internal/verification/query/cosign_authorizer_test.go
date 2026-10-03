package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCosignAuthorizerRequiresScopeAndTenantGrantForHumans(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}}
	r := application.AuthorizationRequest{Scope: "verify:read", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	p := NewCosignVerificationAuthorizer()
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: r.Scope, ScopeOnly: true}); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"verify:read"}}, {ResourceType: "release", ResourceID: "artifact", Scopes: []string{"verify:read"}}, {ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"evidence:read"}}} {
		a.ResourceGrants = []identitydomain.ResourceGrant{grant}
		if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unrelated grant accepted", grant, err)
		}
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	a.ResourceGrants = nil
	a.UserID = ""
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	a.Scopes = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("missing scope accepted", err)
	}
	a.Scopes = []string{"verify:read"}
	r.Resources.ReleaseID = "release"
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unexpected coordinate accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.Authorize(ctx, a, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
