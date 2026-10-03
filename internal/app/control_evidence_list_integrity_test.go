package app

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestListControlEvidenceExcludesBrokenCurrentOwnership(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	now := fixedNow()
	ledger.products["product_a"] = domain.Product{ID: "product_a", TenantID: "tenant_a"}
	ledger.products["product_b"] = domain.Product{ID: "product_b", TenantID: "tenant_a"}
	ledger.releases["release_a"] = domain.Release{ID: "release_a", TenantID: "tenant_a", ProductID: "product_a"}
	ledger.releases["release_b"] = domain.Release{ID: "release_b", TenantID: "tenant_a", ProductID: "product_b"}
	ledger.frameworks["framework_a"] = domain.ControlFramework{ID: "framework_a", TenantID: "tenant_a"}
	ledger.frameworks["framework_other"] = domain.ControlFramework{ID: "framework_other", TenantID: "tenant_other"}
	ledger.controls["control_a"] = domain.SecurityControl{ID: "control_a", TenantID: "tenant_a", FrameworkID: "framework_a"}
	ledger.controls["control_bad_parent"] = domain.SecurityControl{ID: "control_bad_parent", TenantID: "tenant_a", FrameworkID: "framework_other"}
	ledger.evidence["evidence_a"] = domain.EvidenceItem{ID: "evidence_a", TenantID: "tenant_a", ProductID: "product_a", ReleaseID: "release_a"}
	ledger.evidence["evidence_other"] = domain.EvidenceItem{ID: "evidence_other", TenantID: "tenant_other", ProductID: "product_a", ReleaseID: "release_a"}
	ledger.evidence["evidence_b"] = domain.EvidenceItem{ID: "evidence_b", TenantID: "tenant_a", ProductID: "product_b", ReleaseID: "release_b"}
	for _, link := range []domain.ControlEvidence{
		{ID: "valid", TenantID: "tenant_a", ControlID: "control_a", SubjectType: "evidence", SubjectID: "evidence_a", ProductID: "product_a", ReleaseID: "release_a"},
		{ID: "foreign_subject", TenantID: "tenant_a", ControlID: "control_a", SubjectType: "evidence", SubjectID: "evidence_other", ProductID: "product_a", ReleaseID: "release_a"},
		{ID: "wrong_subject_scope", TenantID: "tenant_a", ControlID: "control_a", SubjectType: "evidence", SubjectID: "evidence_b", ProductID: "product_a", ReleaseID: "release_a"},
		{ID: "wrong_release_parent", TenantID: "tenant_a", ControlID: "control_a", SubjectType: "evidence", SubjectID: "evidence_a", ProductID: "product_a", ReleaseID: "release_b"},
		{ID: "missing_control", TenantID: "tenant_a", ControlID: "control_missing", SubjectType: "evidence", SubjectID: "evidence_a", ProductID: "product_a", ReleaseID: "release_a"},
		{ID: "foreign_framework", TenantID: "tenant_a", ControlID: "control_bad_parent", SubjectType: "evidence", SubjectID: "evidence_a", ProductID: "product_a", ReleaseID: "release_a"},
	} {
		link.CreatedAt = now
		ledger.controlLinks[link.ID] = link
	}
	actor := domain.Actor{TenantID: "tenant_a", UserID: "user_a", Scopes: []string{ScopeControlsRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product_a", Scopes: []string{ScopeControlsRead}}}}
	links, err := ledger.ListControlEvidence(context.Background(), actor, "", "", "")
	if err != nil || len(links) != 1 || links[0].ID != "valid" {
		t.Fatalf("scoped control links=%#v error=%v", links, err)
	}
	actor = domain.Actor{TenantID: "tenant_a", KeyID: "key_a", Scopes: []string{ScopeControlsRead}}
	links, err = ledger.ListControlEvidence(context.Background(), actor, "", "", "")
	if err != nil || len(links) != 1 || links[0].ID != "valid" {
		t.Fatalf("credential control links=%#v error=%v", links, err)
	}
}
