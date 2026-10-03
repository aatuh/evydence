package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestDraftAuthorizerSeparatesScopedAndTenantWideAnswers(t *testing.T) {
	p := NewQuestionnaireDraftAuthorizer()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:read"}}}}
	r := application.AuthorizationRequest{Scope: "package:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:read", TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product grant disclosed global answer", err)
	}
	a.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "release", Scopes: []string{"package:read"}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	a.ResourceGrants = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant accepted", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:read", TenantWide: true}); err != nil {
		t.Fatal(err)
	}
	r.Resources.CustomerPackageID = "package"
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unrelated package grant accepted", err)
	}
}
