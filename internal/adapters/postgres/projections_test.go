package postgres

import (
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestResourceProjectionsCoverTenantScopedImplementedResources(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	state := app.PersistedState{
		Tenants:                 map[string]domain.Tenant{"ten_1": {ID: "ten_1", CreatedAt: now}},
		Organizations:           map[string]domain.Organization{"org_1": {ID: "org_1", TenantID: "ten_1", CreatedAt: now}},
		Users:                   map[string]domain.HumanUser{"usr_1": {ID: "usr_1", TenantID: "ten_1", CreatedAt: now}},
		RoleBindings:            map[string]domain.RoleBinding{"rbac_1": {ID: "rbac_1", TenantID: "ten_1", CreatedAt: now}},
		SSOProviders:            map[string]domain.SSOProvider{"sso_1": {ID: "sso_1", TenantID: "ten_1", CreatedAt: now}},
		IdentityLinks:           map[string]domain.UserIdentityLink{"link_1": {ID: "link_1", TenantID: "ten_1", CreatedAt: now}},
		SSOSessions:             map[string]domain.SSOSession{"sess_1": {ID: "sess_1", TenantID: "ten_1", CreatedAt: now}},
		Products:                map[string]domain.Product{"prod_1": {ID: "prod_1", TenantID: "ten_1", CreatedAt: now}},
		Projects:                map[string]domain.Project{"proj_1": {ID: "proj_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}},
		Releases:                map[string]domain.Release{"rel_1": {ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}},
		Artifacts:               map[string]domain.Artifact{"art_1": {ID: "art_1", TenantID: "ten_1", CreatedAt: now}},
		BuildRuns:               map[string]domain.BuildRun{"build_1": {ID: "build_1", TenantID: "ten_1", ProjectID: "proj_1", ReleaseID: "rel_1", CreatedAt: now}},
		BuildAttestations:       map[string]domain.BuildAttestation{"att_1": {ID: "att_1", TenantID: "ten_1", CreatedAt: now}},
		Evidence:                map[string]domain.EvidenceItem{"ev_1": {ID: "ev_1", TenantID: "ten_1", ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", CreatedAt: now}},
		ReleaseCandidates:       map[string]domain.ReleaseCandidate{"rc_1": {ID: "rc_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		ContainerImages:         map[string]domain.ContainerImage{"img_1": {ID: "img_1", TenantID: "ten_1", CreatedAt: now}},
		ArtifactSignatures:      map[string]domain.ArtifactSignature{"asig_1": {ID: "asig_1", TenantID: "ten_1", CreatedAt: now}},
		Repositories:            map[string]domain.SourceRepository{"repo_1": {ID: "repo_1", TenantID: "ten_1", ProjectID: "proj_1", CreatedAt: now}},
		Commits:                 map[string]domain.SourceCommit{"commit_1": {ID: "commit_1", TenantID: "ten_1", CreatedAt: now}},
		Branches:                map[string]domain.SourceBranch{"branch_1": {ID: "branch_1", TenantID: "ten_1", CreatedAt: now}},
		PullRequests:            map[string]domain.PullRequest{"pr_1": {ID: "pr_1", TenantID: "ten_1", CreatedAt: now}},
		Environments:            map[string]domain.DeploymentEnvironment{"env_1": {ID: "env_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}},
		Deployments:             map[string]domain.DeploymentEvent{"dep_1": {ID: "dep_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		Incidents:               map[string]domain.Incident{"inc_1": {ID: "inc_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		TimelineEvents:          map[string]domain.IncidentTimelineEvent{"tl_1": {ID: "tl_1", TenantID: "ten_1", CreatedAt: now}},
		RemediationTasks:        map[string]domain.RemediationTask{"task_1": {ID: "task_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		SecurityScans:           map[string]domain.SecurityScan{"secscan_1": {ID: "secscan_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		ManualSecurityDocs:      map[string]domain.ManualSecurityDocument{"doc_1": {ID: "doc_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		SBOMDiffs:               map[string]domain.SBOMDiff{"diff_1": {ID: "diff_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		DependencyChanges:       map[string]domain.DependencyChange{"depchg_1": {ID: "depchg_1", TenantID: "ten_1", CreatedAt: now}},
		VulnerabilityWorkflow:   map[string]domain.VulnerabilityWorkflowRecord{"vw_1": {ID: "vw_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		ContractDiffs:           map[string]domain.ContractDiff{"cdiff_1": {ID: "cdiff_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		CustomPolicies:          map[string]domain.CustomPolicy{"pol_1": {ID: "pol_1", TenantID: "ten_1", CreatedAt: now}},
		CustomPolicyEvaluations: map[string]domain.CustomPolicyEvaluation{"peval_1": {ID: "peval_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		Waivers:                 map[string]domain.Waiver{"waiver_1": {ID: "waiver_1", TenantID: "ten_1", CreatedAt: now}},
		Approvals:               map[string]domain.ApprovalRecord{"app_1": {ID: "app_1", TenantID: "ten_1", CreatedAt: now}},
		RedactionProfiles:       map[string]domain.RedactionProfile{"red_1": {ID: "red_1", TenantID: "ten_1", CreatedAt: now}},
		CustomerPackages:        map[string]domain.CustomerSecurityPackage{"pkg_1": {ID: "pkg_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		HTMLReports:             map[string]domain.HTMLReportPackage{"html_1": {ID: "html_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		ReportTemplates:         map[string]domain.CustomReportTemplate{"tmpl_1": {ID: "tmpl_1", TenantID: "ten_1", CreatedAt: now}},
		RenderedReports:         map[string]domain.RenderedCustomReport{"rend_1": {ID: "rend_1", TenantID: "ten_1", CreatedAt: now}},
		EvidenceBundles:         map[string]domain.EvidenceBundle{"eb_1": {ID: "eb_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		BundleImports:           map[string]domain.EvidenceBundleImport{"ebi_1": {ID: "ebi_1", TenantID: "ten_1", CreatedAt: now}},
		DSSETrustRoots:          map[string]domain.DSSETrustRoot{"trust_1": {ID: "trust_1", TenantID: "ten_1", CreatedAt: now}},
		CollectorReleases:       map[string]domain.CollectorRelease{"cr_1": {ID: "cr_1", TenantID: "ten_1", CreatedAt: now}},
		CosignVerifications:     map[string]domain.CosignVerification{"cosign_1": {ID: "cosign_1", TenantID: "ten_1", CreatedAt: now}},
		SigningProviders:        map[string]domain.SigningProvider{"sp_1": {ID: "sp_1", TenantID: "ten_1", CreatedAt: now}},
		MerkleBatches:           map[string]domain.MerkleBatch{"mb_1": {ID: "mb_1", TenantID: "ten_1", CreatedAt: now}},
		TransparencyCheckpoints: map[string]domain.TransparencyCheckpoint{"tc_1": {ID: "tc_1", TenantID: "ten_1", CreatedAt: now}},
		ObjectRetentionPolicies: map[string]domain.ObjectRetentionPolicy{"orp_1": {ID: "orp_1", TenantID: "ten_1", CreatedAt: now}},
		BackupManifests:         map[string]domain.BackupManifest{"bak_1": {ID: "bak_1", TenantID: "ten_1", CreatedAt: now}},
		LegalHolds:              map[string]domain.LegalHold{"hold_1": {ID: "hold_1", TenantID: "ten_1", CreatedAt: now}},
		RetentionOverrides:      map[string]domain.RetentionOverride{"ret_1": {ID: "ret_1", TenantID: "ten_1", CreatedAt: now}},
		CustomerPortalAccess:    map[string]domain.CustomerPortalAccess{"cpa_1": {ID: "cpa_1", TenantID: "ten_1", CreatedAt: now}},
		QuestionnaireTemplates:  map[string]domain.QuestionnaireTemplate{"qt_1": {ID: "qt_1", TenantID: "ten_1", CreatedAt: now}},
		QuestionnairePackages:   map[string]domain.QuestionnairePackage{"qp_1": {ID: "qp_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		CommercialCollectors:    map[string]domain.CommercialCollectorDefinition{"cc_1": {ID: "cc_1", TenantID: "ten_1", CreatedAt: now}},
		EvidenceSummaries:       map[string]domain.EvidenceSummary{"sum_1": {ID: "sum_1", TenantID: "ten_1", CreatedAt: now}},
		QuestionnaireDrafts:     map[string]domain.QuestionnaireDraft{"qd_1": {ID: "qd_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		GraphSnapshots:          map[string]domain.EvidenceGraphSnapshot{"graph_1": {ID: "graph_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		SaaSProfiles:            map[string]domain.SaaSEditionProfile{"saas_1": {ID: "saas_1", TenantID: "ten_1", CreatedAt: now}},
		PublicTransparencyLogs:  map[string]domain.PublicTransparencyLog{"ptl_1": {ID: "ptl_1", TenantID: "ten_1", CreatedAt: now}},
		PublicTransparencyItems: map[string]domain.PublicTransparencyLogEntry{"pte_1": {ID: "pte_1", TenantID: "ten_1", CreatedAt: now}},
		MarketplaceCollectors:   map[string]domain.MarketplaceCollector{"mc_1": {ID: "mc_1", TenantID: "ten_1", CreatedAt: now}},
		PDFReports:              map[string]domain.PDFReportPackage{"pdf_1": {ID: "pdf_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		AnomalyReports:          map[string]domain.AnomalyReport{"anom_1": {ID: "anom_1", TenantID: "ten_1", CreatedAt: now}},
		ProviderVerifications:   map[string]domain.ProviderVerification{"pv_1": {ID: "pv_1", TenantID: "ten_1", CreatedAt: now}},
		SigningOperations:       map[string]domain.SigningOperation{"so_1": {ID: "so_1", TenantID: "ten_1", CreatedAt: now}},
		ControlFrameworks:       map[string]domain.ControlFramework{"cf_1": {ID: "cf_1", TenantID: "ten_1", CreatedAt: now}},
		SecurityControls:        map[string]domain.SecurityControl{"ctrl_1": {ID: "ctrl_1", TenantID: "ten_1", CreatedAt: now}},
		ControlEvidence:         map[string]domain.ControlEvidence{"ce_1": {ID: "ce_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		SBOMs:                   map[string]domain.SBOM{"sbom_1": {ID: "sbom_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		Scans:                   map[string]domain.VulnerabilityScan{"scan_1": {ID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		VEXDocuments:            map[string]domain.VEXDocument{"vex_1": {ID: "vex_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
		Contracts:               map[string]domain.OpenAPIContract{"api_1": {ID: "api_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", CreatedAt: now}},
		Bundles:                 map[string]domain.ReleaseBundle{"bundle_1": {ID: "bundle_1", TenantID: "ten_1", ReleaseID: "rel_1", CreatedAt: now}},
	}

	projections := resourceProjections(state)
	if len(projections) != 76 {
		t.Fatalf("projection count = %d, want 76", len(projections))
	}
	byType := map[string]resourceProjection{}
	for _, projection := range projections {
		byType[projection.ResourceType] = projection
		if projection.TenantID != "ten_1" {
			t.Fatalf("projection lost tenant scope: %#v", projection)
		}
	}
	for _, resourceType := range []string{
		"tenant", "product", "project", "release", "evidence_item", "build_run",
		"release_candidate", "deployment", "customer_security_package",
		"control_evidence", "public_transparency_log_entry", "release_bundle",
	} {
		if byType[resourceType].ResourceID == "" {
			t.Fatalf("missing projection type %s in %#v", resourceType, byType)
		}
	}
	if byType["project"].ProductID != "prod_1" || byType["project"].ProjectID != "proj_1" {
		t.Fatalf("project projection = %#v", byType["project"])
	}
	if byType["release"].ProductID != "prod_1" || byType["release"].ReleaseID != "rel_1" {
		t.Fatalf("release projection = %#v", byType["release"])
	}
	if byType["customer_security_package"].ProductID != "prod_1" || byType["customer_security_package"].ReleaseID != "rel_1" {
		t.Fatalf("customer package projection = %#v", byType["customer_security_package"])
	}
	if nullableString("") != nil {
		t.Fatal("empty nullableString should be nil")
	}
	if got := nullableString("prod_1"); got != "prod_1" {
		t.Fatalf("nullableString = %#v", got)
	}
}
