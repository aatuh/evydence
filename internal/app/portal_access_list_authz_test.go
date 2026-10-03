package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestListCustomerPortalAccessEnforcesCurrentResourceGrants(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	now := fixedNow()
	ledger.products["product_a"] = domain.Product{ID: "product_a", TenantID: "tenant_a"}
	ledger.products["product_b"] = domain.Product{ID: "product_b", TenantID: "tenant_a"}
	ledger.releases["release_a"] = domain.Release{ID: "release_a", TenantID: "tenant_a", ProductID: "product_a"}
	ledger.releases["release_b"] = domain.Release{ID: "release_b", TenantID: "tenant_a", ProductID: "product_b"}
	for _, item := range []struct{ id, product, release string }{
		{"package_a", "product_a", "release_a"},
		{"package_b", "product_b", "release_b"},
	} {
		ledger.customerPackages[item.id] = domain.CustomerSecurityPackage{ID: item.id, TenantID: "tenant_a", ProductID: item.product, ReleaseID: item.release}
		ledger.portalAccess[item.id] = domain.CustomerPortalAccess{ID: item.id, TenantID: "tenant_a", PackageID: item.id, Hash: "secret-hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	actor := domain.Actor{TenantID: "tenant_a", UserID: "user_a", Scopes: []string{ScopePackageRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product_a", Scopes: []string{ScopePackageRead}}}}
	listed, err := ledger.ListCustomerPortalAccess(context.Background(), actor, "")
	if err != nil || len(listed) != 1 || listed[0].PackageID != "package_a" || listed[0].Hash != "" {
		t.Fatalf("product-scoped list = %#v, %v", listed, err)
	}
	if _, err := ledger.ListCustomerPortalAccess(context.Background(), actor, "package_b"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted package filter: %v", err)
	}
	actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: "release_b", Scopes: []string{ScopePackageRead}}}
	listed, err = ledger.ListCustomerPortalAccess(context.Background(), actor, "")
	if err != nil || len(listed) != 1 || listed[0].PackageID != "package_b" {
		t.Fatalf("release-scoped list = %#v, %v", listed, err)
	}
	actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "package_a", Scopes: []string{ScopePackageRead}}}
	listed, err = ledger.ListCustomerPortalAccess(context.Background(), actor, "")
	if err != nil || len(listed) != 1 || listed[0].PackageID != "package_a" {
		t.Fatalf("package-scoped list = %#v, %v", listed, err)
	}
}
