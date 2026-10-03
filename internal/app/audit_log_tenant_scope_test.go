package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestListAuditLogRequiresTenantWideHumanGrant(t *testing.T) {
	ledger := NewLedger(Config{})
	actor := domain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{ScopeAdmin},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{ScopeAdmin}}},
	}
	if _, err := ledger.ListAuditLog(t.Context(), actor, AuditLogFilter{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-scoped audit log error=%v", err)
	}
	actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{ScopeAdmin}}}
	if _, err := ledger.ListAuditLog(t.Context(), actor, AuditLogFilter{}); err != nil {
		t.Fatalf("tenant-scoped audit log error=%v", err)
	}
}
