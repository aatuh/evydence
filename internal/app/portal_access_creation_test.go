package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestPortalWritesRequireCurrentPackageGrant(t *testing.T) {
	for _, operation := range []string{"create", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			l := NewLedger(Config{Now: fixedNow})
			l.products["product"] = domain.Product{ID: "product", TenantID: "tenant"}
			l.customerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "product"}
			admin := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}
			in := CreateCustomerPortalAccessInput{PackageID: "package", CustomerName: "Customer", ExpiresAt: fixedNow().Add(time.Hour)}
			access, _, err := l.CreateCustomerPortalAccess(t.Context(), admin, in)
			if err != nil {
				t.Fatal(err)
			}
			human := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{ScopePackageWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "another-product", Scopes: []string{ScopePackageWrite}}}}
			if operation == "create" {
				_, _, err = l.CreateCustomerPortalAccess(t.Context(), human, in)
			} else {
				_, err = l.RevokeCustomerPortalAccess(t.Context(), human, access.ID)
			}
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("unrelated product grant allowed portal %s: %v", operation, err)
			}
			if len(l.portalAccess) != 1 || l.portalAccess[access.ID].RevokedAt != nil {
				t.Fatal("denied portal write changed access records")
			}
		})
	}
}
