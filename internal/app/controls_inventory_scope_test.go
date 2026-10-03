package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestControlsInventoryRequiresTenantWideHumanGrant(t *testing.T) {
	ledger := NewLedger(Config{})
	actor := domain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{ScopeControlsRead},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{ScopeControlsRead}}},
	}
	if _, err := ledger.ListControlFrameworks(t.Context(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-granted framework inventory error=%v", err)
	}
	if _, err := ledger.GetSecurityControl(t.Context(), actor, "ctrl_1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-granted control point error=%v", err)
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_other", Scopes: []string{ScopeControlsRead}}
	if _, err := ledger.ListControlFrameworks(t.Context(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign tenant grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = actor.TenantID
	if _, err := ledger.ListControlFrameworks(t.Context(), actor); err != nil {
		t.Fatalf("tenant-granted framework inventory error=%v", err)
	}
	if _, err := ledger.GetSecurityControl(t.Context(), actor, "ctrl_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant-granted missing control error=%v", err)
	}
}
