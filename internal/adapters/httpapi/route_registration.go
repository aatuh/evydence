package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
)

type routeDef struct {
	method  string
	path    string
	op      specs.Operation
	handler http.Handler
}

func (s *Server) registerRoutes() error {
	for _, route := range s.routeDefinitions() {
		if err := s.routes.Register(routecontracts.Route{Method: route.method, Pattern: route.path, Handler: route.handler, Operation: route.op}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) routeDefinitions() []routeDef {
	groups := [][]routeDef{
		s.systemRoutes(),
		s.identityRoutes(),
		s.collectorRoutes(),
		s.controlRoutes(),
		s.productReleaseRoutes(),
		s.artifactBuildSourceRoutes(),
		s.deploymentIncidentSecurityRoutes(),
		s.packagePortalRoutes(),
		s.evidenceRiskPolicyRoutes(),
		s.integrityOpsRoutes(),
		s.keyAndAdminRoutes(),
	}
	var routes []routeDef
	for _, group := range groups {
		routes = append(routes, group...)
	}
	return routes
}

func (s *Server) systemRoutes() []routeDef {
	return []routeDef{
		{http.MethodGet, "/v1/health", op("health", http.MethodGet, "/v1/health", "Health", nil), http.HandlerFunc(s.health)},
		{http.MethodGet, "/v1/ready", op("ready", http.MethodGet, "/v1/ready", "Readiness", nil), http.HandlerFunc(s.ready)},
		{http.MethodGet, "/v1/version", op("version", http.MethodGet, "/v1/version", "Version", nil), http.HandlerFunc(s.version)},
		{http.MethodGet, "/v1/metrics", op("metrics", http.MethodGet, "/v1/metrics", "Safe tenant metrics", []string{app.ScopeAdmin}), http.HandlerFunc(s.metrics)},
		{http.MethodGet, "/v1/openapi.json", op("openapi", http.MethodGet, "/v1/openapi.json", "OpenAPI", nil), http.HandlerFunc(s.openapi)},
		{http.MethodGet, "/v1/admin/instance", op("instanceAdminSnapshot", http.MethodGet, "/v1/admin/instance", "Instance admin snapshot", []string{app.ScopeInstanceAdmin}), http.HandlerFunc(s.instanceAdminSnapshot)},
	}
}

func (s *Server) identityRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/organizations", op("createOrganization", http.MethodPost, "/v1/organizations", "Create organization", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createOrganization)},
		{http.MethodPost, "/v1/users", op("createUser", http.MethodPost, "/v1/users", "Create user", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createUser)},
		{http.MethodPost, "/v1/users/{id}/deactivate", op("deactivateUser", http.MethodPost, "/v1/users/{id}/deactivate", "Deactivate user", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.deactivateUser)},
		{http.MethodPost, "/v1/role-bindings", op("createRoleBinding", http.MethodPost, "/v1/role-bindings", "Create role binding", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createRoleBinding)},
		{http.MethodGet, "/v1/role-bindings", op("listRoleBindings", http.MethodGet, "/v1/role-bindings", "List role bindings", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.listRoleBindings)},
		{http.MethodPost, "/v1/sso/providers", op("createSSOProvider", http.MethodPost, "/v1/sso/providers", "Create SSO provider", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createSSOProvider)},
		{http.MethodPost, "/v1/sso/providers/{id}/trust-material", op("updateSSOProviderTrustMaterial", http.MethodPost, "/v1/sso/providers/{id}/trust-material", "Update SSO provider trust material", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.updateSSOProviderTrustMaterial)},
		{http.MethodPost, "/v1/sso/providers/{id}/discover-oidc", op("refreshSSOProviderOIDCTrustMaterial", http.MethodPost, "/v1/sso/providers/{id}/discover-oidc", "Refresh SSO provider OIDC trust material", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.refreshSSOProviderOIDCTrustMaterial)},
		{http.MethodPost, "/v1/sso/identity-links", op("linkSSOIdentity", http.MethodPost, "/v1/sso/identity-links", "Link SSO identity", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.linkSSOIdentity)},
		{http.MethodPost, "/v1/sso/sessions", op("createSSOSession", http.MethodPost, "/v1/sso/sessions", "Create SSO session", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createSSOSession)},
		{http.MethodPost, "/v1/sso/session-exchanges", publicPostOp("exchangeSSOCredential", http.MethodPost, "/v1/sso/session-exchanges", "Exchange SSO credential"), http.HandlerFunc(s.exchangeSSOCredential)},
		{http.MethodPost, "/v1/sso/sessions/{id}/revoke", op("revokeSSOSession", http.MethodPost, "/v1/sso/sessions/{id}/revoke", "Revoke SSO session", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.revokeSSOSession)},
		{http.MethodPost, "/v1/sso/logout", authenticatedOp("logoutSSOSession", http.MethodPost, "/v1/sso/logout", "Logout SSO session"), http.HandlerFunc(s.logoutSSOSession)},
	}
}

func (s *Server) collectorRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/collectors", op("createCollector", http.MethodPost, "/v1/collectors", "Create collector", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.createCollector)},
		{http.MethodGet, "/v1/collectors", op("listCollectors", http.MethodGet, "/v1/collectors", "List collectors", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.listCollectors)},
		{http.MethodPost, "/v1/collectors/{id}/releases", op("recordCollectorRelease", http.MethodPost, "/v1/collectors/{id}/releases", "Record collector release evidence", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.recordCollectorRelease)},
		{http.MethodGet, "/v1/collectors/{id}/health", op("collectorHealthReport", http.MethodGet, "/v1/collectors/{id}/health", "Collector health report", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.collectorHealthReport)},
		{http.MethodPost, "/v1/commercial-collectors", op("createCommercialCollector", http.MethodPost, "/v1/commercial-collectors", "Create commercial collector definition", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.createCommercialCollector)},
		{http.MethodGet, "/v1/commercial-collectors", op("listCommercialCollectors", http.MethodGet, "/v1/commercial-collectors", "List commercial collector definitions", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.listCommercialCollectors)},
		{http.MethodPost, "/v1/marketplace-collectors", op("createMarketplaceCollector", http.MethodPost, "/v1/marketplace-collectors", "Create marketplace collector record", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.createMarketplaceCollector)},
		{http.MethodGet, "/v1/marketplace-collectors", op("listMarketplaceCollectors", http.MethodGet, "/v1/marketplace-collectors", "List marketplace collector records", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.listMarketplaceCollectors)},
		{http.MethodGet, "/v1/marketplace-collectors/{id}/health", op("marketplaceCollectorHealth", http.MethodGet, "/v1/marketplace-collectors/{id}/health", "Marketplace collector health report", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.marketplaceCollectorHealth)},
	}
}

func (s *Server) controlRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/control-frameworks", op("createControlFramework", http.MethodPost, "/v1/control-frameworks", "Create control framework", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.createControlFramework)},
		{http.MethodGet, "/v1/control-frameworks", op("listControlFrameworks", http.MethodGet, "/v1/control-frameworks", "List control frameworks", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlFrameworks)},
		{http.MethodGet, "/v1/control-framework-template-packs", op("listControlFrameworkTemplatePacks", http.MethodGet, "/v1/control-framework-template-packs", "List control framework template packs", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlFrameworkTemplatePacks)},
		{http.MethodPost, "/v1/control-framework-template-packs/{slug}/install", op("installControlFrameworkTemplatePack", http.MethodPost, "/v1/control-framework-template-packs/{slug}/install", "Install control framework template pack", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.installControlFrameworkTemplatePack)},
		{http.MethodPost, "/v1/controls", op("createSecurityControl", http.MethodPost, "/v1/controls", "Create security control", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.createSecurityControl)},
		{http.MethodGet, "/v1/controls/{id}", op("getSecurityControl", http.MethodGet, "/v1/controls/{id}", "Get security control", []string{app.ScopeControlsRead}), http.HandlerFunc(s.getSecurityControl)},
		{http.MethodPost, "/v1/controls/{id}/evidence", op("linkControlEvidence", http.MethodPost, "/v1/controls/{id}/evidence", "Link control evidence", []string{app.ScopeControlsWrite}), http.HandlerFunc(s.linkControlEvidence)},
		{http.MethodGet, "/v1/control-evidence", op("listControlEvidence", http.MethodGet, "/v1/control-evidence", "List control evidence", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlEvidence)},
		{http.MethodGet, "/v1/reports/control-coverage", op("controlCoverageReport", http.MethodGet, "/v1/reports/control-coverage", "Control coverage report", []string{app.ScopeReportRead}), http.HandlerFunc(s.controlCoverageReport)},
		{http.MethodGet, "/v1/reports/cra-readiness", op("craReadinessReport", http.MethodGet, "/v1/reports/cra-readiness", "CRA readiness report", []string{app.ScopeReportRead}), http.HandlerFunc(s.craReadinessReport)},
	}
}

func (s *Server) productReleaseRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/products", op("createProduct", http.MethodPost, "/v1/products", "Create product", []string{app.ScopeProductWrite}), http.HandlerFunc(s.createProduct)},
		{http.MethodGet, "/v1/products", op("listProducts", http.MethodGet, "/v1/products", "List products", []string{app.ScopeProductRead}), http.HandlerFunc(s.listProducts)},
		{http.MethodPost, "/v1/projects", op("createProject", http.MethodPost, "/v1/projects", "Create project", []string{app.ScopeProjectWrite}), http.HandlerFunc(s.createProject)},
		{http.MethodPost, "/v1/releases", op("createRelease", http.MethodPost, "/v1/releases", "Create release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createRelease)},
		{http.MethodGet, "/v1/releases/{id}", op("getRelease", http.MethodGet, "/v1/releases/{id}", "Get release", []string{app.ScopeReleaseRead}), http.HandlerFunc(s.getRelease)},
		{http.MethodPost, "/v1/releases/{id}/freeze", op("freezeRelease", http.MethodPost, "/v1/releases/{id}/freeze", "Freeze release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.freezeRelease)},
		{http.MethodPost, "/v1/releases/{id}/approve", op("approveRelease", http.MethodPost, "/v1/releases/{id}/approve", "Approve release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.approveRelease)},
		{http.MethodPost, "/v1/release-candidates", op("createReleaseCandidate", http.MethodPost, "/v1/release-candidates", "Create release candidate", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createReleaseCandidate)},
		{http.MethodGet, "/v1/release-candidates", op("listReleaseCandidates", http.MethodGet, "/v1/release-candidates", "List release candidates", []string{app.ScopeReleaseRead}), http.HandlerFunc(s.listReleaseCandidates)},
		{http.MethodGet, "/v1/release-candidates/{id}", op("getReleaseCandidate", http.MethodGet, "/v1/release-candidates/{id}", "Get release candidate", []string{app.ScopeReleaseRead}), http.HandlerFunc(s.getReleaseCandidate)},
		{http.MethodPost, "/v1/release-candidates/{id}/promote", op("promoteReleaseCandidate", http.MethodPost, "/v1/release-candidates/{id}/promote", "Promote release candidate", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.promoteReleaseCandidate)},
		{http.MethodPost, "/v1/release-candidates/{id}/reject", op("rejectReleaseCandidate", http.MethodPost, "/v1/release-candidates/{id}/reject", "Reject release candidate", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.rejectReleaseCandidate)},
	}
}

func (s *Server) artifactBuildSourceRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/artifacts", op("registerArtifact", http.MethodPost, "/v1/artifacts", "Register artifact", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.registerArtifact)},
		{http.MethodPost, "/v1/container-images", op("registerContainerImage", http.MethodPost, "/v1/container-images", "Register container image", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.registerContainerImage)},
		{http.MethodPost, "/v1/artifact-signatures", op("createArtifactSignature", http.MethodPost, "/v1/artifact-signatures", "Create artifact signature", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createArtifactSignature)},
		{http.MethodGet, "/v1/artifact-signatures/{id}", op("getArtifactSignature", http.MethodGet, "/v1/artifact-signatures/{id}", "Get artifact signature", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getArtifactSignature)},
		{http.MethodPost, "/v1/artifact-signatures/{id}/verify-cosign", op("verifyCosignSignature", http.MethodPost, "/v1/artifact-signatures/{id}/verify-cosign", "Verify cosign-style artifact signature", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyCosignSignature)},
		{http.MethodPost, "/v1/builds", op("createBuild", http.MethodPost, "/v1/builds", "Create build run", []string{app.ScopeBuildWrite}), http.HandlerFunc(s.createBuild)},
		{http.MethodGet, "/v1/builds/{id}", op("getBuild", http.MethodGet, "/v1/builds/{id}", "Get build run", []string{app.ScopeBuildRead}), http.HandlerFunc(s.getBuild)},
		{http.MethodPost, "/v1/builds/{id}/attestations", op("uploadBuildAttestation", http.MethodPost, "/v1/builds/{id}/attestations", "Upload build attestation", []string{app.ScopeBuildWrite}), http.HandlerFunc(s.uploadBuildAttestation)},
		{http.MethodPost, "/v1/build-attestations/{id}/verify-signature", op("verifyBuildAttestationSignature", http.MethodPost, "/v1/build-attestations/{id}/verify-signature", "Verify build attestation signature", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyBuildAttestationSignature)},
		{http.MethodPost, "/v1/dsse-trust-roots", op("createDSSETrustRoot", http.MethodPost, "/v1/dsse-trust-roots", "Create DSSE trust root", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createDSSETrustRoot)},
		{http.MethodPost, "/v1/source/repositories", op("createSourceRepository", http.MethodPost, "/v1/source/repositories", "Create source repository", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.createSourceRepository)},
		{http.MethodGet, "/v1/source/repositories", op("listSourceRepositories", http.MethodGet, "/v1/source/repositories", "List source repositories", []string{app.ScopeSourceRead}), http.HandlerFunc(s.listSourceRepositories)},
		{http.MethodPost, "/v1/source/commits", op("recordSourceCommit", http.MethodPost, "/v1/source/commits", "Record source commit", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.recordSourceCommit)},
		{http.MethodPost, "/v1/source/branches", op("upsertSourceBranch", http.MethodPost, "/v1/source/branches", "Record source branch", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.upsertSourceBranch)},
		{http.MethodPost, "/v1/source/pull-requests", op("recordPullRequest", http.MethodPost, "/v1/source/pull-requests", "Record pull request", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.recordPullRequest)},
		{http.MethodPost, "/v1/collectors/github/source-snapshots", op("uploadGitHubSourceSnapshot", http.MethodPost, "/v1/collectors/github/source-snapshots", "Upload GitHub source snapshot", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.uploadGitHubSourceSnapshot)},
		{http.MethodPost, "/v1/collectors/gitlab/source-snapshots", op("uploadGitLabSourceSnapshot", http.MethodPost, "/v1/collectors/gitlab/source-snapshots", "Upload GitLab source snapshot", []string{app.ScopeSourceWrite}), http.HandlerFunc(s.uploadGitLabSourceSnapshot)},
	}
}

func (s *Server) deploymentIncidentSecurityRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/environments", op("createDeploymentEnvironment", http.MethodPost, "/v1/environments", "Create deployment environment", []string{app.ScopeDeploymentWrite}), http.HandlerFunc(s.createDeploymentEnvironment)},
		{http.MethodGet, "/v1/environments", op("listDeploymentEnvironments", http.MethodGet, "/v1/environments", "List deployment environments", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.listDeploymentEnvironments)},
		{http.MethodPost, "/v1/deployments", op("recordDeployment", http.MethodPost, "/v1/deployments", "Record deployment", []string{app.ScopeDeploymentWrite}), http.HandlerFunc(s.recordDeployment)},
		{http.MethodGet, "/v1/deployments", op("listDeployments", http.MethodGet, "/v1/deployments", "List deployments", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.listDeployments)},
		{http.MethodGet, "/v1/deployments/{id}", op("getDeployment", http.MethodGet, "/v1/deployments/{id}", "Get deployment", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.getDeployment)},
		{http.MethodPost, "/v1/incidents", op("createIncident", http.MethodPost, "/v1/incidents", "Create incident", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.createIncident)},
		{http.MethodPost, "/v1/incidents/{id}/timeline", op("recordIncidentTimeline", http.MethodPost, "/v1/incidents/{id}/timeline", "Record incident timeline event", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.recordIncidentTimeline)},
		{http.MethodPost, "/v1/incidents/{id}/webhook-receivers", op("createIncidentWebhookReceiver", http.MethodPost, "/v1/incidents/{id}/webhook-receivers", "Create signed incident webhook receiver", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.createIncidentWebhookReceiver)},
		{http.MethodPost, "/v1/incident-webhooks/{receiver_id}", op("receiveIncidentWebhook", http.MethodPost, "/v1/incident-webhooks/{receiver_id}", "Receive signed incident webhook event", nil), http.HandlerFunc(s.receiveIncidentWebhook)},
		{http.MethodPost, "/v1/remediation-tasks", op("createRemediationTask", http.MethodPost, "/v1/remediation-tasks", "Create remediation task", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.createRemediationTask)},
		{http.MethodGet, "/v1/reports/incident-package", op("incidentReport", http.MethodGet, "/v1/reports/incident-package", "Incident package report", []string{app.ScopeIncidentRead}), http.HandlerFunc(s.incidentReport)},
		{http.MethodPost, "/v1/security-scans", op("uploadSecurityScan", http.MethodPost, "/v1/security-scans", "Upload security scan", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadSecurityScan)},
		{http.MethodPost, "/v1/api-security-scans", op("uploadAPISecurityScan", http.MethodPost, "/v1/api-security-scans", "Upload API security scan", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadAPISecurityScan)},
		{http.MethodPost, "/v1/security-documents", op("uploadManualSecurityDocument", http.MethodPost, "/v1/security-documents", "Upload manual security document", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadManualSecurityDocument)},
	}
}

func (s *Server) packagePortalRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/waivers", op("createWaiver", http.MethodPost, "/v1/waivers", "Create waiver", []string{app.ScopePolicyWrite}), http.HandlerFunc(s.createWaiver)},
		{http.MethodPost, "/v1/waivers/{id}/approve", op("approveWaiver", http.MethodPost, "/v1/waivers/{id}/approve", "Approve waiver", []string{app.ScopePolicyWrite}), http.HandlerFunc(s.approveWaiver)},
		{http.MethodPost, "/v1/approvals", op("createApproval", http.MethodPost, "/v1/approvals", "Create approval record", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createApproval)},
		{http.MethodPost, "/v1/redaction-profiles", op("createRedactionProfile", http.MethodPost, "/v1/redaction-profiles", "Create redaction profile", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createRedactionProfile)},
		{http.MethodPost, "/v1/customer-packages", op("createCustomerPackage", http.MethodPost, "/v1/customer-packages", "Create customer security package", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createCustomerPackage)},
		{http.MethodGet, "/v1/customer-packages/{id}", op("getCustomerPackage", http.MethodGet, "/v1/customer-packages/{id}", "Get customer security package", []string{app.ScopePackageRead}), http.HandlerFunc(s.getCustomerPackage)},
		{http.MethodGet, "/v1/customer-packages/{id}/download", op("downloadCustomerPackage", http.MethodGet, "/v1/customer-packages/{id}/download", "Download customer security package ZIP", []string{app.ScopePackageRead}), http.HandlerFunc(s.downloadCustomerPackage)},
		{http.MethodPost, "/v1/customer-portal/access", op("createCustomerPortalAccess", http.MethodPost, "/v1/customer-portal/access", "Create customer portal access", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createCustomerPortalAccess)},
		{http.MethodPost, "/v1/customer-portal/package", op("accessCustomerPortalPackage", http.MethodPost, "/v1/customer-portal/package", "Access customer portal package", nil), http.HandlerFunc(s.accessCustomerPortalPackage)},
		{http.MethodPost, "/v1/customer-portal/package/download", op("downloadCustomerPortalPackage", http.MethodPost, "/v1/customer-portal/package/download", "Download customer portal package ZIP", nil), http.HandlerFunc(s.downloadCustomerPortalPackage)},
		{http.MethodPost, "/v1/questionnaire-templates", op("createQuestionnaireTemplate", http.MethodPost, "/v1/questionnaire-templates", "Create questionnaire template", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createQuestionnaireTemplate)},
		{http.MethodPost, "/v1/questionnaire-packages", op("createQuestionnairePackage", http.MethodPost, "/v1/questionnaire-packages", "Create questionnaire package", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createQuestionnairePackage)},
		{http.MethodPost, "/v1/questionnaire-drafts", op("createQuestionnaireDraft", http.MethodPost, "/v1/questionnaire-drafts", "Create evidence-backed questionnaire draft", []string{app.ScopePackageRead}), http.HandlerFunc(s.createQuestionnaireDraft)},
		{http.MethodGet, "/v1/reports/security-review-package", op("securityReviewPackageReport", http.MethodGet, "/v1/reports/security-review-package", "Security review package report", []string{app.ScopePackageRead}), http.HandlerFunc(s.securityReviewPackageReport)},
		{http.MethodGet, "/v1/reports/cra-readiness-html", op("craReadinessHTMLPackage", http.MethodGet, "/v1/reports/cra-readiness-html", "CRA readiness HTML package", []string{app.ScopeReportRead}), http.HandlerFunc(s.craReadinessHTMLPackage)},
		{http.MethodPost, "/v1/reports/pdf", op("createPDFReportPackage", http.MethodPost, "/v1/reports/pdf", "Create reproducible PDF report package", []string{app.ScopeReportRead}), http.HandlerFunc(s.createPDFReportPackage)},
		{http.MethodPost, "/v1/report-templates", op("createReportTemplate", http.MethodPost, "/v1/report-templates", "Create report template", []string{app.ScopeReportRead}), http.HandlerFunc(s.createReportTemplate)},
		{http.MethodPost, "/v1/report-templates/{id}/render", op("renderReportTemplate", http.MethodPost, "/v1/report-templates/{id}/render", "Render report template", []string{app.ScopeReportRead}), http.HandlerFunc(s.renderReportTemplate)},
	}
}

func (s *Server) evidenceRiskPolicyRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/evidence-bundles", op("exportEvidenceBundle", http.MethodPost, "/v1/evidence-bundles", "Export evidence bundle", []string{app.ScopeBundleRead}), http.HandlerFunc(s.exportEvidenceBundle)},
		{http.MethodPost, "/v1/evidence-bundles/import", op("importEvidenceBundle", http.MethodPost, "/v1/evidence-bundles/import", "Import evidence bundle", []string{app.ScopeBundleWrite}), http.HandlerFunc(s.importEvidenceBundle)},
		{http.MethodPost, "/v1/sboms/spdx", op("uploadSPDXSBOM", http.MethodPost, "/v1/sboms/spdx", "Upload SPDX SBOM", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadSPDXSBOM)},
		{http.MethodPost, "/v1/sbom-diffs", op("createSBOMDiff", http.MethodPost, "/v1/sbom-diffs", "Create SBOM diff", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.createSBOMDiff)},
		{http.MethodPost, "/v1/evidence", op("createEvidence", http.MethodPost, "/v1/evidence", "Create evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createEvidence)},
		{http.MethodGet, "/v1/evidence", op("listEvidence", http.MethodGet, "/v1/evidence", "List evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listEvidence)},
		{http.MethodGet, "/v1/evidence/search", op("searchEvidence", http.MethodGet, "/v1/evidence/search", "Search evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.searchEvidence)},
		{http.MethodPost, "/v1/evidence-summaries", op("createEvidenceSummary", http.MethodPost, "/v1/evidence-summaries", "Create evidence-backed summary", []string{app.ScopeReportRead}), http.HandlerFunc(s.createEvidenceSummary)},
		{http.MethodPost, "/v1/evidence-graph-snapshots", op("createGraphSnapshot", http.MethodPost, "/v1/evidence-graph-snapshots", "Create evidence graph snapshot", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.createGraphSnapshot)},
		{http.MethodGet, "/v1/evidence/{id}", op("getEvidence", http.MethodGet, "/v1/evidence/{id}", "Get evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/supersede", op("supersedeEvidence", http.MethodPost, "/v1/evidence/{id}/supersede", "Supersede evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.supersedeEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/link", op("linkEvidence", http.MethodPost, "/v1/evidence/{id}/link", "Link evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.linkEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/lifecycle-events", op("recordEvidenceLifecycleEvent", http.MethodPost, "/v1/evidence/{id}/lifecycle-events", "Record evidence lifecycle event", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.recordEvidenceLifecycleEvent)},
		{http.MethodGet, "/v1/evidence/{id}/lifecycle-events", op("listEvidenceLifecycleEvents", http.MethodGet, "/v1/evidence/{id}/lifecycle-events", "List evidence lifecycle events", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listEvidenceLifecycleEvents)},
		{http.MethodPost, "/v1/sboms", op("uploadSBOM", http.MethodPost, "/v1/sboms", "Upload CycloneDX SBOM", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadSBOM)},
		{http.MethodGet, "/v1/sboms/{id}", op("getSBOM", http.MethodGet, "/v1/sboms/{id}", "Get SBOM", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getSBOM)},
		{http.MethodGet, "/v1/sbom-components", op("listSBOMComponents", http.MethodGet, "/v1/sbom-components", "List SBOM components", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listSBOMComponents)},
		{http.MethodPost, "/v1/vex", op("uploadVEX", http.MethodPost, "/v1/vex", "Upload OpenVEX document", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadVEX)},
		{http.MethodPost, "/v1/vex/cyclonedx", op("uploadCycloneDXVEX", http.MethodPost, "/v1/vex/cyclonedx", "Upload CycloneDX VEX document", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadCycloneDXVEX)},
		{http.MethodGet, "/v1/vex/{id}", op("getVEX", http.MethodGet, "/v1/vex/{id}", "Get VEX document", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getVEX)},
		{http.MethodPost, "/v1/vulnerability-scans", op("uploadVulnerabilityScan", http.MethodPost, "/v1/vulnerability-scans", "Upload vulnerability scan", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadVulnerabilityScan)},
		{http.MethodGet, "/v1/vulnerability-scans/{id}", op("getVulnerabilityScan", http.MethodGet, "/v1/vulnerability-scans/{id}", "Get vulnerability scan", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getVulnerabilityScan)},
		{http.MethodPost, "/v1/vulnerability-findings/{id}/decisions", op("createVulnerabilityDecision", http.MethodPost, "/v1/vulnerability-findings/{id}/decisions", "Create vulnerability decision", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createVulnerabilityDecision)},
		{http.MethodPost, "/v1/vulnerability-findings/{id}/workflow", op("recordVulnerabilityWorkflow", http.MethodPost, "/v1/vulnerability-findings/{id}/workflow", "Record vulnerability workflow event", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.recordVulnerabilityWorkflow)},
		{http.MethodGet, "/v1/reports/vulnerability-posture", op("vulnerabilityPostureReport", http.MethodGet, "/v1/reports/vulnerability-posture", "Vulnerability posture report", []string{app.ScopeSecurityRead}), http.HandlerFunc(s.vulnerabilityPostureReport)},
		{http.MethodPost, "/v1/openapi-contracts", op("uploadOpenAPIContract", http.MethodPost, "/v1/openapi-contracts", "Upload OpenAPI contract", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadOpenAPIContract)},
		{http.MethodGet, "/v1/openapi-contracts/{id}", op("getOpenAPIContract", http.MethodGet, "/v1/openapi-contracts/{id}", "Get OpenAPI contract", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getOpenAPIContract)},
		{http.MethodPost, "/v1/openapi-diffs", op("createOpenAPIDiff", http.MethodPost, "/v1/openapi-diffs", "Create OpenAPI contract diff", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.createOpenAPIDiff)},
		{http.MethodPost, "/v1/policies/evaluate", op("evaluatePolicy", http.MethodPost, "/v1/policies/evaluate", "Evaluate release policy", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.evaluatePolicy)},
		{http.MethodPost, "/v1/custom-policies", op("createCustomPolicy", http.MethodPost, "/v1/custom-policies", "Create custom policy", []string{app.ScopePolicyWrite}), http.HandlerFunc(s.createCustomPolicy)},
		{http.MethodPost, "/v1/custom-policies/{id}/evaluate", op("evaluateCustomPolicy", http.MethodPost, "/v1/custom-policies/{id}/evaluate", "Evaluate custom policy", []string{app.ScopePolicyRead}), http.HandlerFunc(s.evaluateCustomPolicy)},
		{http.MethodPost, "/v1/exceptions", op("createException", http.MethodPost, "/v1/exceptions", "Create exception", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createException)},
		{http.MethodGet, "/v1/exceptions", op("listExceptions", http.MethodGet, "/v1/exceptions", "List exceptions", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.listExceptions)},
		{http.MethodPost, "/v1/exceptions/{id}/approve", op("approveException", http.MethodPost, "/v1/exceptions/{id}/approve", "Approve exception", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.approveException)},
		{http.MethodGet, "/v1/reports/missing-evidence", op("missingEvidenceReport", http.MethodGet, "/v1/reports/missing-evidence", "Missing evidence report", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.missingEvidenceReport)},
		{http.MethodGet, "/v1/reports/release-readiness", op("releaseReadinessReport", http.MethodGet, "/v1/reports/release-readiness", "Release readiness report", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.releaseReadinessReport)},
		{http.MethodPost, "/v1/reports/anomaly", op("generateAnomalyReport", http.MethodPost, "/v1/reports/anomaly", "Generate deterministic anomaly report", []string{app.ScopeReportRead}), http.HandlerFunc(s.generateAnomalyReport)},
	}
}

func (s *Server) integrityOpsRoutes() []routeDef {
	return []routeDef{
		{http.MethodPost, "/v1/release-bundles", op("createReleaseBundle", http.MethodPost, "/v1/release-bundles", "Create release bundle", []string{app.ScopeBundleWrite}), http.HandlerFunc(s.createReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}", op("getReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}", "Get release bundle", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}/manifest", op("getReleaseBundleManifest", http.MethodGet, "/v1/release-bundles/{id}/manifest", "Get release bundle manifest", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundleManifest)},
		{http.MethodGet, "/v1/release-bundles/{id}/verify", op("verifyReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}/verify", "Verify release bundle", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyReleaseBundle)},
		{http.MethodGet, "/v1/audit-chain/verify", op("verifyAuditChain", http.MethodGet, "/v1/audit-chain/verify", "Verify audit chain", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyAuditChain)},
		{http.MethodGet, "/v1/audit-log", op("listAuditLog", http.MethodGet, "/v1/audit-log", "List tenant audit log", []string{app.ScopeAdmin}), http.HandlerFunc(s.listAuditLog)},
		{http.MethodPost, "/v1/merkle-batches", op("createMerkleBatch", http.MethodPost, "/v1/merkle-batches", "Create Merkle checkpoint batch", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createMerkleBatch)},
		{http.MethodGet, "/v1/merkle-batches/{id}/verify", op("verifyMerkleBatch", http.MethodGet, "/v1/merkle-batches/{id}/verify", "Verify Merkle checkpoint batch", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyMerkleBatch)},
		{http.MethodPost, "/v1/transparency-checkpoints", op("createTransparencyCheckpoint", http.MethodPost, "/v1/transparency-checkpoints", "Record external transparency checkpoint", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createTransparencyCheckpoint)},
		{http.MethodPost, "/v1/public-transparency-logs", op("createPublicTransparencyLog", http.MethodPost, "/v1/public-transparency-logs", "Create public transparency log record", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createPublicTransparencyLog)},
		{http.MethodPost, "/v1/public-transparency-log-entries", op("publishPublicTransparencyLogEntry", http.MethodPost, "/v1/public-transparency-log-entries", "Publish public transparency log entry record", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.publishPublicTransparencyLogEntry)},
		{http.MethodPost, "/v1/public-transparency-log-entries/{id}/verify", op("verifyPublicTransparencyLogEntry", http.MethodPost, "/v1/public-transparency-log-entries/{id}/verify", "Verify public transparency log inclusion proof", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.verifyPublicTransparencyLogEntry)},
		{http.MethodPost, "/v1/public-transparency-log-entries/{id}/fetch-proof", op("fetchPublicTransparencyLogEntryProof", http.MethodPost, "/v1/public-transparency-log-entries/{id}/fetch-proof", "Fetch and verify public transparency log inclusion proof", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.fetchPublicTransparencyLogEntryProof)},
		{http.MethodPost, "/v1/object-retention-policies", op("createObjectRetentionPolicy", http.MethodPost, "/v1/object-retention-policies", "Create object retention policy record", []string{app.ScopeAdmin}), http.HandlerFunc(s.createObjectRetentionPolicy)},
		{http.MethodPost, "/v1/object-retention-policies/{id}/verify", op("verifyObjectRetentionPolicy", http.MethodPost, "/v1/object-retention-policies/{id}/verify", "Verify object retention policy record", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyObjectRetentionPolicy)},
		{http.MethodPost, "/v1/legal-holds", op("createLegalHold", http.MethodPost, "/v1/legal-holds", "Create legal hold", []string{app.ScopeAdmin}), http.HandlerFunc(s.createLegalHold)},
		{http.MethodPost, "/v1/retention-overrides", op("createRetentionOverride", http.MethodPost, "/v1/retention-overrides", "Create retention override", []string{app.ScopeAdmin}), http.HandlerFunc(s.createRetentionOverride)},
		{http.MethodGet, "/v1/reports/retention", op("retentionReport", http.MethodGet, "/v1/reports/retention", "Retention report", []string{app.ScopeAdmin}), http.HandlerFunc(s.retentionReport)},
		{http.MethodPost, "/v1/backup-manifests", op("generateBackupManifest", http.MethodPost, "/v1/backup-manifests", "Generate backup manifest", []string{app.ScopeAdmin}), http.HandlerFunc(s.generateBackupManifest)},
		{http.MethodGet, "/v1/backup-manifests/{id}/verify", op("verifyBackupManifest", http.MethodGet, "/v1/backup-manifests/{id}/verify", "Verify backup manifest", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyBackupManifest)},
	}
}

func (s *Server) keyAndAdminRoutes() []routeDef {
	return []routeDef{
		{http.MethodGet, "/v1/signing-keys", op("listSigningKeys", http.MethodGet, "/v1/signing-keys", "List signing keys", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.listSigningKeys)},
		{http.MethodPost, "/v1/signing-keys/rotate", op("rotateSigningKey", http.MethodPost, "/v1/signing-keys/rotate", "Rotate signing key", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.rotateSigningKey)},
		{http.MethodPost, "/v1/signing-keys/{id}/revoke", op("revokeSigningKey", http.MethodPost, "/v1/signing-keys/{id}/revoke", "Revoke signing key", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.revokeSigningKey)},
		{http.MethodPost, "/v1/signing-providers", op("createSigningProvider", http.MethodPost, "/v1/signing-providers", "Create signing provider record", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createSigningProvider)},
		{http.MethodPost, "/v1/signing-operations", op("createSigningOperation", http.MethodPost, "/v1/signing-operations", "Create signing provider operation receipt", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createSigningOperation)},
		{http.MethodPost, "/v1/provider-verifications", op("verifyProviderIdentity", http.MethodPost, "/v1/provider-verifications", "Verify stored provider identity metadata", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.verifyProviderIdentity)},
		{http.MethodPost, "/v1/saas/profiles", op("createSaaSEditionProfile", http.MethodPost, "/v1/saas/profiles", "Create SaaS edition profile", []string{app.ScopeInstanceAdmin}), http.HandlerFunc(s.createSaaSEditionProfile)},
		{http.MethodPost, "/v1/verify", op("verify", http.MethodPost, "/v1/verify", "Verify subject", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifySubject)},
		{http.MethodPost, "/v1/api-keys", op("createAPIKey", http.MethodPost, "/v1/api-keys", "Create API key", []string{app.ScopeAdmin}), http.HandlerFunc(s.createAPIKey)},
		{http.MethodGet, "/v1/api-keys", op("listAPIKeys", http.MethodGet, "/v1/api-keys", "List API keys", []string{app.ScopeAdmin}), http.HandlerFunc(s.listAPIKeys)},
	}
}
