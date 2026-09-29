package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestCollectorHealthRequiresTenantWideHumanGrant(t *testing.T) {
	ledger := NewLedger(Config{})
	actor := domain.Actor{TenantID: "ten_1", KeyID: "key_admin", Scopes: []string{ScopeCollectorAdmin}}
	collector, _, _, err := ledger.CreateCollector(t.Context(), actor, CreateCollectorInput{Name: "health-scope", Type: collectorTypeGenericCI, Version: "1", Scopes: []string{ScopeEvidenceWrite}})
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: actor.TenantID, UserID: "usr_health", Scopes: []string{ScopeCollectorRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_other", Scopes: []string{ScopeCollectorRead}}}}
	if _, err := ledger.CollectorHealthReport(t.Context(), human, collector.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("product-only grant error=%v", err)
	}
	human.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{ScopeCollectorRead}}
	if _, err := ledger.CollectorHealthReport(t.Context(), human, collector.ID); err != nil {
		t.Fatalf("tenant-granted health error=%v", err)
	}
}
