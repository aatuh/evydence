package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCustomerCreationAuthorizerRequiresSelectedProductOrReleaseGrant(t *testing.T) {
	p := NewCustomerPackageCreationAuthorizer()
	refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "tenant", "package:write", true}, {"product", "product", "package:write", true}, {"release", "release", "package:write", true},
		{"tenant", "other", "package:write", false}, {"product", "other", "package:write", false}, {"release", "other", "package:write", false},
		{"project", "project", "package:write", false}, {"customer_security_package", "package", "package:write", false}, {"product", "product", "package:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}}
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", Resources: refs}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grants accepted", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", Resources: refs}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []application.AuthorizationRequest{
		{Scope: "package:write", Resources: application.ResourceReferences{ReleaseID: "release"}},
		{Scope: "package:read", Resources: refs},
		{Scope: "package:write", Resources: application.ResourceReferences{ProductID: "product", CustomerPackageID: "package"}},
		{Scope: "package:write", TenantWide: true, Resources: refs},
	} {
		if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unrelated boundary accepted", err)
		}
	}
}
