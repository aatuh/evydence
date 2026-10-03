package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestQuestionnairePackageAuthorizerSeparatesAssociationAndSelection(t *testing.T) {
	p := NewQuestionnairePackageAuthorizer()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "package", Scopes: []string{"package:write"}}}}
	r := application.AuthorizationRequest{Scope: "package:write", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release", CustomerPackageID: "package"}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("package grant rejected association", err)
	}
	for _, request := range []application.AuthorizationRequest{{Scope: "package:write", TenantWide: true}, {Scope: "package:write", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}, {Scope: "package:write", Resources: application.ResourceReferences{CustomerPackageID: "package"}}, {Scope: "package:read", Resources: r.Resources}, {Scope: "package:write", ScopeOnly: true, Resources: r.Resources}} {
		if err := p.Authorize(t.Context(), a, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("package grant broadened selection", err)
		}
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:write"}}}
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("product grant rejected association", err)
	}
	r.Resources.CustomerPackageID = ""
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("product grant rejected selection", err)
	}
	a.ResourceGrants = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grants retain access", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", TenantWide: true}); err != nil {
		t.Fatal("tenant key denied", err)
	}
	a.Scopes = []string{"package:read"}
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("read credential writes", err)
	}
}
