package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestEnterpriseGovernanceAndFutureHelperBranches(t *testing.T) {
	now := fixedNow()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ledger.mu.Lock()
	ledger.tenants["ten_1"] = domain.Tenant{ID: "ten_1", CreatedAt: now}
	ledger.products["prod_1"] = domain.Product{ID: "prod_1", TenantID: "ten_1", CreatedAt: now}
	ledger.projects["proj_1"] = domain.Project{ID: "proj_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}
	ledger.releases["rel_1"] = domain.Release{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}
	ledger.artifacts["art_1"] = domain.Artifact{ID: "art_1", TenantID: "ten_1", CreatedAt: now}
	ledger.evidence["ev_1"] = domain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", Type: "sbom", CreatedAt: now}
	ledger.users["usr_1"] = domain.HumanUser{ID: "usr_1", TenantID: "ten_1", CreatedAt: now}
	ledger.collectors["col_1"] = domain.Collector{ID: "col_1", TenantID: "ten_1", CreatedAt: now}
	ledger.customerPackages["pkg_1"] = domain.CustomerSecurityPackage{ID: "pkg_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.evidenceBundles["eb_1"] = domain.EvidenceBundle{ID: "eb_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.buildRuns["build_1"] = domain.BuildRun{ID: "build_1", TenantID: "ten_1", ProjectID: "proj_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.repositories["repo_1"] = domain.SourceRepository{ID: "repo_1", TenantID: "ten_1", ProjectID: "proj_1", CreatedAt: now}
	ledger.deployments["dep_1"] = domain.DeploymentEvent{ID: "dep_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.environments["env_1"] = domain.DeploymentEnvironment{ID: "env_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}
	ledger.incidents["inc_1"] = domain.Incident{ID: "inc_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.securityScans["sec_1"] = domain.SecurityScan{ID: "sec_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}
	ledger.frameworks["fw_1"] = domain.ControlFramework{ID: "fw_1", TenantID: "ten_1", Slug: "b", Version: "1", CreatedAt: now}
	ledger.frameworks["fw_2"] = domain.ControlFramework{ID: "fw_2", TenantID: "ten_1", Slug: "a", Version: "1", CreatedAt: now}
	ledger.controls["ctrl_1"] = domain.SecurityControl{ID: "ctrl_1", TenantID: "ten_1", FrameworkID: "fw_1", CreatedAt: now}
	ledger.customPolicies["pol_1"] = domain.CustomPolicy{ID: "pol_1", TenantID: "ten_1", CreatedAt: now}
	ledger.scans["scan_1"] = domain.VulnerabilityScan{ID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Severity: "critical", State: "open"}}, CreatedAt: now}
	ledger.contractDiffs["cdiff_1"] = domain.ContractDiff{ID: "cdiff_1", TenantID: "ten_1", CreatedAt: now}
	ledger.waivers["waiver_1"] = domain.Waiver{ID: "waiver_1", TenantID: "ten_1", ScopeType: "release", ScopeID: "rel_1", CreatedAt: now}
	ledger.manualDocs["review_1"] = domain.ManualSecurityDocument{ID: "review_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", DocumentType: "security_review", CreatedAt: now}
	ledger.controlLinks["ce_1"] = domain.ControlEvidence{ID: "ce_1", TenantID: "ten_1", ControlID: "ctrl_1", SubjectType: "evidence", SubjectID: "ev_1", EvidenceType: "sbom", ProductID: "prod_1", ReleaseID: "rel_1", Confidence: confidenceHigh, CreatedAt: now}
	ledger.roleBindings["rb_1"] = domain.RoleBinding{ID: "rb_1", TenantID: "ten_1", SubjectType: "user", SubjectID: "usr_1", Role: "security_engineer", ResourceType: "release", ResourceID: "rel_1", CreatedAt: now}
	ledger.mu.Unlock()

	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	for _, subject := range []struct{ typ, id string }{{"user", "usr_1"}, {"collector", "col_1"}} {
		if err := ledger.ensureRoleSubjectLocked("ten_1", subject.typ, subject.id); err != nil {
			t.Fatalf("role subject %s: %v", subject.typ, err)
		}
	}
	if !errors.Is(ledger.ensureRoleSubjectLocked("ten_1", "team", "team_1"), ErrValidation) {
		t.Fatal("unknown role subject should be validation")
	}
	for _, scope := range []struct{ typ, id string }{{"tenant", "ten_1"}, {"product", "prod_1"}, {"project", "proj_1"}, {"release", "rel_1"}, {"evidence", "ev_1"}} {
		if err := ledger.ensureRetentionScopeLocked("ten_1", scope.typ, scope.id); err != nil {
			t.Fatalf("retention scope %s: %v", scope.typ, err)
		}
	}
	if !errors.Is(ledger.ensureRetentionScopeLocked("ten_1", "unknown", "id"), ErrValidation) {
		t.Fatal("unknown retention scope should be validation")
	}
	for _, resource := range []struct{ typ, id string }{{"", ""}, {"tenant", "ten_1"}, {"product", "prod_1"}, {"project", "proj_1"}, {"release", "rel_1"}, {"customer_security_package", "pkg_1"}, {"evidence_bundle", "eb_1"}} {
		if err := ledger.ensureRoleResourceLocked("ten_1", resource.typ, resource.id); err != nil {
			t.Fatalf("role resource %s: %v", resource.typ, err)
		}
	}
	if !errors.Is(ledger.ensureRoleResourceLocked("ten_1", "", "unexpected"), ErrValidation) {
		t.Fatal("empty resource type with id should be validation")
	}
	if !validRoleSubject("user") || !validRoleSubject("collector") || validRoleSubject("group") {
		t.Fatal("role subject validation mismatch")
	}
	for _, role := range []string{"tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector"} {
		if !validRole(role) {
			t.Fatalf("valid role rejected: %s", role)
		}
	}
	if validRole("owner") {
		t.Fatal("invalid role accepted")
	}
	grants := ledger.resourceGrantsForUserLocked("usr_1")
	if len(grants) != 1 || !grantHasScope(grants[0], ScopeEvidenceRead) {
		t.Fatalf("resource grants = %#v", grants)
	}
	if scopes := scopesFromResourceGrants(grants); len(scopes) == 0 {
		t.Fatal("scopes from grants should not be empty")
	}

	refs := resourceRefs{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", SourceRepositoryID: "repo_1", CustomerPackageID: "pkg_1", EvidenceBundleID: "eb_1"}
	for _, grant := range []domain.ResourceGrant{
		{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{ScopeEvidenceRead}},
		{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{ScopeEvidenceRead}},
		{ResourceType: "project", ResourceID: "proj_1", Scopes: []string{ScopeEvidenceRead}},
		{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{ScopeEvidenceRead}},
		{ResourceType: "customer_security_package", ResourceID: "pkg_1", Scopes: []string{ScopeEvidenceRead}},
		{ResourceType: "evidence_bundle", ResourceID: "eb_1", Scopes: []string{ScopeEvidenceRead}},
	} {
		if !ledger.grantCoversResourceLocked("ten_1", grant, refs) {
			t.Fatalf("grant should cover refs: %#v", grant)
		}
	}
	if ledger.grantCoversResourceLocked("ten_1", domain.ResourceGrant{ResourceType: "unknown", ResourceID: "id"}, refs) {
		t.Fatal("unknown grant resource should not cover refs")
	}

	for _, subject := range []struct{ typ, id string }{
		{"tenant", "ten_1"}, {"product", "prod_1"}, {"release", "rel_1"}, {"evidence", "ev_1"}, {"build", "build_1"}, {"customer_package", "pkg_1"},
	} {
		if _, err := ledger.ensureFutureSubjectLocked("ten_1", subject.typ, subject.id); err != nil {
			t.Fatalf("future subject %s: %v", subject.typ, err)
		}
	}
	if !errors.Is(mustErrFuture(ledger.ensureFutureSubjectLocked("ten_1", "unknown", "id")), ErrValidation) {
		t.Fatal("unknown future subject should be validation")
	}
	ids := ledger.evidenceIDsForQuestionLocked("ten_1", domain.QuestionnaireQuestion{ControlID: "ctrl_1"}, "prod_1", "rel_1")
	if len(ids) != 1 || ids[0] != "ev_1" {
		t.Fatalf("control question evidence ids = %#v", ids)
	}
	ids = ledger.evidenceIDsForQuestionLocked("ten_1", domain.QuestionnaireQuestion{EvidenceType: "sbom"}, "prod_1", "rel_1")
	if len(ids) != 1 || ids[0] != "ev_1" {
		t.Fatalf("typed question evidence ids = %#v", ids)
	}
	if !evidenceMatchesRefs(ledger.evidence["ev_1"], resourceRefs{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1"}) {
		t.Fatal("evidence should match refs")
	}
	if evidenceMatchesRefs(ledger.evidence["ev_1"], resourceRefs{ProductID: "other"}) || evidenceMatchesRefs(ledger.evidence["ev_1"], resourceRefs{ProjectID: "other"}) || evidenceMatchesRefs(ledger.evidence["ev_1"], resourceRefs{ReleaseID: "other"}) {
		t.Fatal("evidence should not match wrong refs")
	}
	items := []domain.MarketplaceCollector{{ID: "z"}, {ID: "a"}, {ID: "m"}}
	sortMarketplaceCollectors(items)
	if items[0].ID != "a" || items[2].ID != "z" {
		t.Fatalf("marketplace sort = %#v", items)
	}

	for _, scope := range []string{"release", "finding", "control", "policy"} {
		if !validWaiverScope(scope) {
			t.Fatalf("valid waiver scope rejected: %s", scope)
		}
	}
	for _, subject := range []string{"release", "contract_diff", "waiver", "security_review", "customer_package"} {
		if !validApprovalSubject(subject) {
			t.Fatalf("valid approval subject rejected: %s", subject)
		}
	}
	if !validApprovalDecision("approved") || !validApprovalDecision("rejected") || validApprovalDecision("maybe") {
		t.Fatal("approval decision validation mismatch")
	}
	for _, scope := range []struct{ typ, id string }{{"release", "rel_1"}, {"control", "ctrl_1"}, {"policy", "pol_1"}, {"finding", "finding_1"}} {
		if err := ledger.ensureWaiverScopeLocked("ten_1", scope.typ, scope.id); err != nil {
			t.Fatalf("waiver scope %s: %v", scope.typ, err)
		}
	}
	for _, subject := range []struct{ typ, id string }{{"release", "rel_1"}, {"contract_diff", "cdiff_1"}, {"waiver", "waiver_1"}, {"security_review", "review_1"}, {"customer_package", "pkg_1"}} {
		if err := ledger.ensureApprovalSubjectLocked("ten_1", subject.typ, subject.id); err != nil {
			t.Fatalf("approval subject %s: %v", subject.typ, err)
		}
	}
	if first := ledger.firstFrameworkIDLocked("ten_1"); first != "fw_2" {
		t.Fatalf("first framework = %s", first)
	}
}

func mustErrFuture(_ resourceRefs, err error) error { return err }
