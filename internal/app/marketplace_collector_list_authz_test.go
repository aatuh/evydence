package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMarketplaceCollectorReadsRequireTenantGrantForHumanSession(t *testing.T) {
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test"})
	tenant, _, _, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	ledger.marketplaceCollectors["market_1"] = domain.MarketplaceCollector{ID: "market_1", TenantID: tenant.ID}
	actor := domain.Actor{TenantID: tenant.ID, UserID: "user_1", Scopes: []string{ScopeCollectorRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{ScopeCollectorRead}}}}
	if _, err := ledger.ListMarketplaceCollectors(t.Context(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-scoped list error=%v", err)
	}
	if _, err := ledger.MarketplaceCollectorHealth(t.Context(), actor, "market_1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-scoped health error=%v", err)
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: tenant.ID, Scopes: []string{ScopeCollectorRead}}
	if values, err := ledger.ListMarketplaceCollectors(t.Context(), actor); err != nil || len(values) != 1 {
		t.Fatalf("tenant list=%#v error=%v", values, err)
	}
}
