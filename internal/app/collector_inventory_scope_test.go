package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestListCollectorsRequiresTenantWideHumanGrant(t *testing.T) {
	ledger := newLegacyLedgerFixture(Config{})
	actor := domain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{ScopeCollectorRead},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{ScopeCollectorRead}}},
	}
	if _, err := ledger.ListCollectors(t.Context(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-scoped collector inventory error=%v", err)
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_other", Scopes: []string{ScopeCollectorRead}}
	if _, err := ledger.ListCollectors(t.Context(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign-tenant collector inventory error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = actor.TenantID
	if _, err := ledger.ListCollectors(t.Context(), actor); err != nil {
		t.Fatalf("tenant-granted collector inventory error=%v", err)
	}
}
