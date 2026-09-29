package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestListCommercialCollectorDefinitionsRequiresTenantGrant(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ledger.commercialCollectors["commercial_1"] = domain.CommercialCollectorDefinition{ID: "commercial_1", TenantID: "tenant_a", Name: "Scanner", CreatedAt: fixedNow()}
	actor := domain.Actor{TenantID: "tenant_a", UserID: "user_a", Scopes: []string{ScopeCollectorRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product_a", Scopes: []string{ScopeCollectorRead}}}}
	if _, err := ledger.ListCommercialCollectorDefinitions(context.Background(), actor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-only grant error=%v", err)
	}
	actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: "tenant_a", Scopes: []string{ScopeCollectorRead}}
	definitions, err := ledger.ListCommercialCollectorDefinitions(context.Background(), actor)
	if err != nil || len(definitions) != 1 || definitions[0].ID != "commercial_1" {
		t.Fatalf("tenant-granted list=%#v error=%v", definitions, err)
	}
}
