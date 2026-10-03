package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPortalAccessWriteAuthorizerUsesCurrentPackageGrant(t *testing.T) {
	refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release", CustomerPackageID: "package"}
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "tenant", "package:write", true}, {"product", "product", "package:write", true}, {"release", "release", "package:write", true}, {"customer_security_package", "package", "package:write", true},
		{"product", "other", "package:write", false}, {"release", "other", "package:write", false}, {"customer_security_package", "other", "package:write", false}, {"tenant", "other", "package:write", false}, {"customer_security_package", "package", "package:read", false}, {"project", "project", "package:write", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := NewPortalAccessWriteAuthorizer().Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal("portal grant policy differs", err)
			}
		})
	}
}
