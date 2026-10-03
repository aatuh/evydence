package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestAnswerLibraryWriteAuthorizerRequiresCurrentScopeAndResourceGrant(t *testing.T) {
	p := NewAnswerLibraryAuthorizer()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:write"}}}}
	r := application.AuthorizationRequest{Scope: "package:write", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product writer created global entry", err)
	}
	a.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "release", Scopes: []string{"package:write"}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	a.ResourceGrants = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant accepted", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", TenantWide: true}); err != nil {
		t.Fatal(err)
	}
	a.Scopes = []string{"package:read"}
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("read scope can write", err)
	}
	if err := p.Authorize(t.Context(), identitydomain.Actor{}, r); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("anonymous writer", err)
	}
}
