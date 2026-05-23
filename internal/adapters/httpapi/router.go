package httpapi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"
	"github.com/aatuh/api-toolkit/v3/idempotent"
	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const maxJSONBody = 2 << 20
const requestIDHeader = "X-Request-ID"

type Server struct {
	ledger *app.Ledger
	mux    *http.ServeMux
	specs  *specs.Registry
	routes *routecontracts.Registry
}

func NewServer(ledger *app.Ledger) (*Server, error) {
	if ledger == nil {
		ledger = app.NewLedger(app.Config{})
	}
	mux := http.NewServeMux()
	specRegistry := NewSpecRegistry()
	router := &serveMuxRouter{mux: mux}
	routeRegistry := routecontracts.NewRegistry(router, specRegistry)
	server := &Server{ledger: ledger, mux: mux, specs: specRegistry, routes: routeRegistry}
	if err := server.registerRoutes(); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return secureHeaders(requestIDMiddleware(s.mux))
}

func (s *Server) OpenAPI() ([]byte, error) {
	return s.specs.OpenAPI()
}

func (s *Server) ValidateRoutes() error {
	return s.routes.Validate()
}

func (s *Server) registerRoutes() error {
	routes := []struct {
		method  string
		path    string
		op      specs.Operation
		handler http.Handler
	}{
		{http.MethodGet, "/v1/health", op("health", http.MethodGet, "/v1/health", "Health", nil), http.HandlerFunc(s.health)},
		{http.MethodGet, "/v1/ready", op("ready", http.MethodGet, "/v1/ready", "Readiness", nil), http.HandlerFunc(s.ready)},
		{http.MethodGet, "/v1/version", op("version", http.MethodGet, "/v1/version", "Version", nil), http.HandlerFunc(s.version)},
		{http.MethodGet, "/v1/metrics", op("metrics", http.MethodGet, "/v1/metrics", "Safe tenant metrics", []string{app.ScopeAdmin}), http.HandlerFunc(s.metrics)},
		{http.MethodGet, "/v1/openapi.json", op("openapi", http.MethodGet, "/v1/openapi.json", "OpenAPI", nil), http.HandlerFunc(s.openapi)},
		{http.MethodGet, "/v1/admin/instance", op("instanceAdminSnapshot", http.MethodGet, "/v1/admin/instance", "Instance admin snapshot", []string{app.ScopeInstanceAdmin}), http.HandlerFunc(s.instanceAdminSnapshot)},
		{http.MethodPost, "/v1/organizations", op("createOrganization", http.MethodPost, "/v1/organizations", "Create organization", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createOrganization)},
		{http.MethodPost, "/v1/users", op("createUser", http.MethodPost, "/v1/users", "Create user", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createUser)},
		{http.MethodPost, "/v1/users/{id}/deactivate", op("deactivateUser", http.MethodPost, "/v1/users/{id}/deactivate", "Deactivate user", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.deactivateUser)},
		{http.MethodPost, "/v1/role-bindings", op("createRoleBinding", http.MethodPost, "/v1/role-bindings", "Create role binding", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createRoleBinding)},
		{http.MethodGet, "/v1/role-bindings", op("listRoleBindings", http.MethodGet, "/v1/role-bindings", "List role bindings", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.listRoleBindings)},
		{http.MethodPost, "/v1/sso/providers", op("createSSOProvider", http.MethodPost, "/v1/sso/providers", "Create SSO provider", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createSSOProvider)},
		{http.MethodPost, "/v1/sso/identity-links", op("linkSSOIdentity", http.MethodPost, "/v1/sso/identity-links", "Link SSO identity", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.linkSSOIdentity)},
		{http.MethodPost, "/v1/sso/sessions", op("createSSOSession", http.MethodPost, "/v1/sso/sessions", "Create SSO session", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.createSSOSession)},
		{http.MethodPost, "/v1/sso/sessions/{id}/revoke", op("revokeSSOSession", http.MethodPost, "/v1/sso/sessions/{id}/revoke", "Revoke SSO session", []string{app.ScopeIdentityAdmin}), http.HandlerFunc(s.revokeSSOSession)},
		{http.MethodPost, "/v1/collectors", op("createCollector", http.MethodPost, "/v1/collectors", "Create collector", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.createCollector)},
		{http.MethodGet, "/v1/collectors", op("listCollectors", http.MethodGet, "/v1/collectors", "List collectors", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.listCollectors)},
		{http.MethodPost, "/v1/collectors/{id}/releases", op("recordCollectorRelease", http.MethodPost, "/v1/collectors/{id}/releases", "Record collector release evidence", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.recordCollectorRelease)},
		{http.MethodGet, "/v1/collectors/{id}/health", op("collectorHealthReport", http.MethodGet, "/v1/collectors/{id}/health", "Collector health report", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.collectorHealthReport)},
		{http.MethodPost, "/v1/control-frameworks", op("createControlFramework", http.MethodPost, "/v1/control-frameworks", "Create control framework", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.createControlFramework)},
		{http.MethodGet, "/v1/control-frameworks", op("listControlFrameworks", http.MethodGet, "/v1/control-frameworks", "List control frameworks", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlFrameworks)},
		{http.MethodGet, "/v1/control-framework-template-packs", op("listControlFrameworkTemplatePacks", http.MethodGet, "/v1/control-framework-template-packs", "List control framework template packs", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlFrameworkTemplatePacks)},
		{http.MethodPost, "/v1/control-framework-template-packs/{slug}/install", op("installControlFrameworkTemplatePack", http.MethodPost, "/v1/control-framework-template-packs/{slug}/install", "Install control framework template pack", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.installControlFrameworkTemplatePack)},
		{http.MethodPost, "/v1/controls", op("createSecurityControl", http.MethodPost, "/v1/controls", "Create security control", []string{app.ScopeControlsAdmin}), http.HandlerFunc(s.createSecurityControl)},
		{http.MethodGet, "/v1/controls/{id}", op("getSecurityControl", http.MethodGet, "/v1/controls/{id}", "Get security control", []string{app.ScopeControlsRead}), http.HandlerFunc(s.getSecurityControl)},
		{http.MethodPost, "/v1/controls/{id}/evidence", op("linkControlEvidence", http.MethodPost, "/v1/controls/{id}/evidence", "Link control evidence", []string{app.ScopeControlsWrite}), http.HandlerFunc(s.linkControlEvidence)},
		{http.MethodGet, "/v1/control-evidence", op("listControlEvidence", http.MethodGet, "/v1/control-evidence", "List control evidence", []string{app.ScopeControlsRead}), http.HandlerFunc(s.listControlEvidence)},
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
		{http.MethodPost, "/v1/environments", op("createDeploymentEnvironment", http.MethodPost, "/v1/environments", "Create deployment environment", []string{app.ScopeDeploymentWrite}), http.HandlerFunc(s.createDeploymentEnvironment)},
		{http.MethodGet, "/v1/environments", op("listDeploymentEnvironments", http.MethodGet, "/v1/environments", "List deployment environments", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.listDeploymentEnvironments)},
		{http.MethodPost, "/v1/deployments", op("recordDeployment", http.MethodPost, "/v1/deployments", "Record deployment", []string{app.ScopeDeploymentWrite}), http.HandlerFunc(s.recordDeployment)},
		{http.MethodGet, "/v1/deployments", op("listDeployments", http.MethodGet, "/v1/deployments", "List deployments", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.listDeployments)},
		{http.MethodGet, "/v1/deployments/{id}", op("getDeployment", http.MethodGet, "/v1/deployments/{id}", "Get deployment", []string{app.ScopeDeploymentRead}), http.HandlerFunc(s.getDeployment)},
		{http.MethodPost, "/v1/incidents", op("createIncident", http.MethodPost, "/v1/incidents", "Create incident", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.createIncident)},
		{http.MethodPost, "/v1/incidents/{id}/timeline", op("recordIncidentTimeline", http.MethodPost, "/v1/incidents/{id}/timeline", "Record incident timeline event", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.recordIncidentTimeline)},
		{http.MethodPost, "/v1/remediation-tasks", op("createRemediationTask", http.MethodPost, "/v1/remediation-tasks", "Create remediation task", []string{app.ScopeIncidentWrite}), http.HandlerFunc(s.createRemediationTask)},
		{http.MethodGet, "/v1/reports/incident-package", op("incidentReport", http.MethodGet, "/v1/reports/incident-package", "Incident package report", []string{app.ScopeIncidentRead}), http.HandlerFunc(s.incidentReport)},
		{http.MethodPost, "/v1/security-scans", op("uploadSecurityScan", http.MethodPost, "/v1/security-scans", "Upload security scan", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadSecurityScan)},
		{http.MethodPost, "/v1/api-security-scans", op("uploadAPISecurityScan", http.MethodPost, "/v1/api-security-scans", "Upload API security scan", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadAPISecurityScan)},
		{http.MethodPost, "/v1/security-documents", op("uploadManualSecurityDocument", http.MethodPost, "/v1/security-documents", "Upload manual security document", []string{app.ScopeSecurityWrite}), http.HandlerFunc(s.uploadManualSecurityDocument)},
		{http.MethodPost, "/v1/waivers", op("createWaiver", http.MethodPost, "/v1/waivers", "Create waiver", []string{app.ScopePolicyWrite}), http.HandlerFunc(s.createWaiver)},
		{http.MethodPost, "/v1/waivers/{id}/approve", op("approveWaiver", http.MethodPost, "/v1/waivers/{id}/approve", "Approve waiver", []string{app.ScopePolicyWrite}), http.HandlerFunc(s.approveWaiver)},
		{http.MethodPost, "/v1/approvals", op("createApproval", http.MethodPost, "/v1/approvals", "Create approval record", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createApproval)},
		{http.MethodPost, "/v1/redaction-profiles", op("createRedactionProfile", http.MethodPost, "/v1/redaction-profiles", "Create redaction profile", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createRedactionProfile)},
		{http.MethodPost, "/v1/customer-packages", op("createCustomerPackage", http.MethodPost, "/v1/customer-packages", "Create customer security package", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createCustomerPackage)},
		{http.MethodGet, "/v1/customer-packages/{id}", op("getCustomerPackage", http.MethodGet, "/v1/customer-packages/{id}", "Get customer security package", []string{app.ScopePackageRead}), http.HandlerFunc(s.getCustomerPackage)},
		{http.MethodPost, "/v1/customer-portal/access", op("createCustomerPortalAccess", http.MethodPost, "/v1/customer-portal/access", "Create customer portal access", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createCustomerPortalAccess)},
		{http.MethodPost, "/v1/customer-portal/package", op("accessCustomerPortalPackage", http.MethodPost, "/v1/customer-portal/package", "Access customer portal package", nil), http.HandlerFunc(s.accessCustomerPortalPackage)},
		{http.MethodPost, "/v1/questionnaire-templates", op("createQuestionnaireTemplate", http.MethodPost, "/v1/questionnaire-templates", "Create questionnaire template", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createQuestionnaireTemplate)},
		{http.MethodPost, "/v1/questionnaire-packages", op("createQuestionnairePackage", http.MethodPost, "/v1/questionnaire-packages", "Create questionnaire package", []string{app.ScopePackageWrite}), http.HandlerFunc(s.createQuestionnairePackage)},
		{http.MethodGet, "/v1/reports/security-review-package", op("securityReviewPackageReport", http.MethodGet, "/v1/reports/security-review-package", "Security review package report", []string{app.ScopePackageRead}), http.HandlerFunc(s.securityReviewPackageReport)},
		{http.MethodGet, "/v1/reports/cra-readiness-html", op("craReadinessHTMLPackage", http.MethodGet, "/v1/reports/cra-readiness-html", "CRA readiness HTML package", []string{app.ScopeReportRead}), http.HandlerFunc(s.craReadinessHTMLPackage)},
		{http.MethodPost, "/v1/report-templates", op("createReportTemplate", http.MethodPost, "/v1/report-templates", "Create report template", []string{app.ScopeReportRead}), http.HandlerFunc(s.createReportTemplate)},
		{http.MethodPost, "/v1/report-templates/{id}/render", op("renderReportTemplate", http.MethodPost, "/v1/report-templates/{id}/render", "Render report template", []string{app.ScopeReportRead}), http.HandlerFunc(s.renderReportTemplate)},
		{http.MethodPost, "/v1/evidence-bundles", op("exportEvidenceBundle", http.MethodPost, "/v1/evidence-bundles", "Export evidence bundle", []string{app.ScopeBundleRead}), http.HandlerFunc(s.exportEvidenceBundle)},
		{http.MethodPost, "/v1/evidence-bundles/import", op("importEvidenceBundle", http.MethodPost, "/v1/evidence-bundles/import", "Import evidence bundle", []string{app.ScopeBundleWrite}), http.HandlerFunc(s.importEvidenceBundle)},
		{http.MethodPost, "/v1/sboms/spdx", op("uploadSPDXSBOM", http.MethodPost, "/v1/sboms/spdx", "Upload SPDX SBOM", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadSPDXSBOM)},
		{http.MethodPost, "/v1/sbom-diffs", op("createSBOMDiff", http.MethodPost, "/v1/sbom-diffs", "Create SBOM diff", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.createSBOMDiff)},
		{http.MethodPost, "/v1/evidence", op("createEvidence", http.MethodPost, "/v1/evidence", "Create evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createEvidence)},
		{http.MethodGet, "/v1/evidence", op("listEvidence", http.MethodGet, "/v1/evidence", "List evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listEvidence)},
		{http.MethodGet, "/v1/evidence/search", op("searchEvidence", http.MethodGet, "/v1/evidence/search", "Search evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.searchEvidence)},
		{http.MethodGet, "/v1/evidence/{id}", op("getEvidence", http.MethodGet, "/v1/evidence/{id}", "Get evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/supersede", op("supersedeEvidence", http.MethodPost, "/v1/evidence/{id}/supersede", "Supersede evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.supersedeEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/link", op("linkEvidence", http.MethodPost, "/v1/evidence/{id}/link", "Link evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.linkEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/lifecycle-events", op("recordEvidenceLifecycleEvent", http.MethodPost, "/v1/evidence/{id}/lifecycle-events", "Record evidence lifecycle event", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.recordEvidenceLifecycleEvent)},
		{http.MethodGet, "/v1/evidence/{id}/lifecycle-events", op("listEvidenceLifecycleEvents", http.MethodGet, "/v1/evidence/{id}/lifecycle-events", "List evidence lifecycle events", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listEvidenceLifecycleEvents)},
		{http.MethodPost, "/v1/sboms", op("uploadSBOM", http.MethodPost, "/v1/sboms", "Upload CycloneDX SBOM", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadSBOM)},
		{http.MethodGet, "/v1/sboms/{id}", op("getSBOM", http.MethodGet, "/v1/sboms/{id}", "Get SBOM", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getSBOM)},
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
		{http.MethodGet, "/v1/reports/control-coverage", op("controlCoverageReport", http.MethodGet, "/v1/reports/control-coverage", "Control coverage report", []string{app.ScopeReportRead}), http.HandlerFunc(s.controlCoverageReport)},
		{http.MethodGet, "/v1/reports/cra-readiness", op("craReadinessReport", http.MethodGet, "/v1/reports/cra-readiness", "CRA readiness report", []string{app.ScopeReportRead}), http.HandlerFunc(s.craReadinessReport)},
		{http.MethodPost, "/v1/release-bundles", op("createReleaseBundle", http.MethodPost, "/v1/release-bundles", "Create release bundle", []string{app.ScopeBundleWrite}), http.HandlerFunc(s.createReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}", op("getReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}", "Get release bundle", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}/manifest", op("getReleaseBundleManifest", http.MethodGet, "/v1/release-bundles/{id}/manifest", "Get release bundle manifest", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundleManifest)},
		{http.MethodGet, "/v1/release-bundles/{id}/verify", op("verifyReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}/verify", "Verify release bundle", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyReleaseBundle)},
		{http.MethodGet, "/v1/audit-chain/verify", op("verifyAuditChain", http.MethodGet, "/v1/audit-chain/verify", "Verify audit chain", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyAuditChain)},
		{http.MethodGet, "/v1/audit-log", op("listAuditLog", http.MethodGet, "/v1/audit-log", "List tenant audit log", []string{app.ScopeAdmin}), http.HandlerFunc(s.listAuditLog)},
		{http.MethodPost, "/v1/merkle-batches", op("createMerkleBatch", http.MethodPost, "/v1/merkle-batches", "Create Merkle checkpoint batch", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createMerkleBatch)},
		{http.MethodGet, "/v1/merkle-batches/{id}/verify", op("verifyMerkleBatch", http.MethodGet, "/v1/merkle-batches/{id}/verify", "Verify Merkle checkpoint batch", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyMerkleBatch)},
		{http.MethodPost, "/v1/transparency-checkpoints", op("createTransparencyCheckpoint", http.MethodPost, "/v1/transparency-checkpoints", "Record external transparency checkpoint", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createTransparencyCheckpoint)},
		{http.MethodPost, "/v1/object-retention-policies", op("createObjectRetentionPolicy", http.MethodPost, "/v1/object-retention-policies", "Create object retention policy record", []string{app.ScopeAdmin}), http.HandlerFunc(s.createObjectRetentionPolicy)},
		{http.MethodPost, "/v1/object-retention-policies/{id}/verify", op("verifyObjectRetentionPolicy", http.MethodPost, "/v1/object-retention-policies/{id}/verify", "Verify object retention policy record", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyObjectRetentionPolicy)},
		{http.MethodPost, "/v1/legal-holds", op("createLegalHold", http.MethodPost, "/v1/legal-holds", "Create legal hold", []string{app.ScopeAdmin}), http.HandlerFunc(s.createLegalHold)},
		{http.MethodPost, "/v1/retention-overrides", op("createRetentionOverride", http.MethodPost, "/v1/retention-overrides", "Create retention override", []string{app.ScopeAdmin}), http.HandlerFunc(s.createRetentionOverride)},
		{http.MethodGet, "/v1/reports/retention", op("retentionReport", http.MethodGet, "/v1/reports/retention", "Retention report", []string{app.ScopeAdmin}), http.HandlerFunc(s.retentionReport)},
		{http.MethodPost, "/v1/backup-manifests", op("generateBackupManifest", http.MethodPost, "/v1/backup-manifests", "Generate backup manifest", []string{app.ScopeAdmin}), http.HandlerFunc(s.generateBackupManifest)},
		{http.MethodGet, "/v1/backup-manifests/{id}/verify", op("verifyBackupManifest", http.MethodGet, "/v1/backup-manifests/{id}/verify", "Verify backup manifest", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyBackupManifest)},
		{http.MethodGet, "/v1/signing-keys", op("listSigningKeys", http.MethodGet, "/v1/signing-keys", "List signing keys", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.listSigningKeys)},
		{http.MethodPost, "/v1/signing-keys/rotate", op("rotateSigningKey", http.MethodPost, "/v1/signing-keys/rotate", "Rotate signing key", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.rotateSigningKey)},
		{http.MethodPost, "/v1/signing-keys/{id}/revoke", op("revokeSigningKey", http.MethodPost, "/v1/signing-keys/{id}/revoke", "Revoke signing key", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.revokeSigningKey)},
		{http.MethodPost, "/v1/signing-providers", op("createSigningProvider", http.MethodPost, "/v1/signing-providers", "Create signing provider record", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.createSigningProvider)},
		{http.MethodPost, "/v1/commercial-collectors", op("createCommercialCollector", http.MethodPost, "/v1/commercial-collectors", "Create commercial collector definition", []string{app.ScopeCollectorAdmin}), http.HandlerFunc(s.createCommercialCollector)},
		{http.MethodGet, "/v1/commercial-collectors", op("listCommercialCollectors", http.MethodGet, "/v1/commercial-collectors", "List commercial collector definitions", []string{app.ScopeCollectorRead}), http.HandlerFunc(s.listCommercialCollectors)},
		{http.MethodPost, "/v1/verify", op("verify", http.MethodPost, "/v1/verify", "Verify subject", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifySubject)},
		{http.MethodPost, "/v1/api-keys", op("createAPIKey", http.MethodPost, "/v1/api-keys", "Create API key", []string{app.ScopeAdmin}), http.HandlerFunc(s.createAPIKey)},
		{http.MethodGet, "/v1/api-keys", op("listAPIKeys", http.MethodGet, "/v1/api-keys", "List API keys", []string{app.ScopeAdmin}), http.HandlerFunc(s.listAPIKeys)},
	}
	for _, route := range routes {
		if err := s.routes.Register(routecontracts.Route{Method: route.method, Pattern: route.path, Handler: route.handler, Operation: route.op}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) createCollector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		Version string   `json:"version"`
		Scopes  []string `json:"scopes"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		collector, key, secret, err := s.ledger.CreateCollector(r.Context(), actor, app.CreateCollectorInput{
			Name:    req.Name,
			Type:    req.Type,
			Version: req.Version,
			Scopes:  req.Scopes,
		})
		return http.StatusCreated, map[string]any{"collector": collector, "api_key": key, "secret": secret}, err
	})
}

func (s *Server) listCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	collectors, err := s.ledger.ListCollectors(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, collectors)
}

func (s *Server) recordCollectorRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version        string `json:"version"`
		ArtifactDigest string `json:"artifact_digest"`
		SignatureID    string `json:"signature_id"`
		SBOMID         string `json:"sbom_id"`
		ScanID         string `json:"scan_id"`
		Pinned         bool   `json:"pinned"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.ledger.RecordCollectorRelease(r.Context(), actor, app.RecordCollectorReleaseInput{
			CollectorID:    r.PathValue("id"),
			Version:        req.Version,
			ArtifactDigest: req.ArtifactDigest,
			SignatureID:    req.SignatureID,
			SBOMID:         req.SBOMID,
			ScanID:         req.ScanID,
			Pinned:         req.Pinned,
		})
		return http.StatusCreated, release, err
	})
}

func (s *Server) collectorHealthReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CollectorHealthReport(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createControlFramework(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Version     string `json:"version"`
		Description string `json:"description"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		framework, err := s.ledger.CreateControlFramework(r.Context(), actor, app.CreateControlFrameworkInput{
			Name:        req.Name,
			Slug:        req.Slug,
			Version:     req.Version,
			Description: req.Description,
		})
		return http.StatusCreated, framework, err
	})
}

func (s *Server) listControlFrameworks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	frameworks, err := s.ledger.ListControlFrameworks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, frameworks)
}

func (s *Server) listControlFrameworkTemplatePacks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	packs, err := s.ledger.ListControlFrameworkTemplatePacks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, packs)
}

func (s *Server) installControlFrameworkTemplatePack(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		framework, err := s.ledger.InstallControlFrameworkTemplatePack(r.Context(), actor, r.PathValue("slug"))
		return http.StatusCreated, framework, err
	})
}

func (s *Server) createSecurityControl(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FrameworkID          string                              `json:"framework_id"`
		Code                 string                              `json:"code"`
		Title                string                              `json:"title"`
		Objective            string                              `json:"objective"`
		EvidenceRequirements []domain.ControlEvidenceRequirement `json:"evidence_requirements"`
		Applicability        []string                            `json:"applicability"`
		Limitations          []string                            `json:"limitations"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		control, err := s.ledger.CreateSecurityControl(r.Context(), actor, app.CreateSecurityControlInput{
			FrameworkID:          req.FrameworkID,
			Code:                 req.Code,
			Title:                req.Title,
			Objective:            req.Objective,
			EvidenceRequirements: req.EvidenceRequirements,
			Applicability:        req.Applicability,
			Limitations:          req.Limitations,
		})
		return http.StatusCreated, control, err
	})
}

func (s *Server) getSecurityControl(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	control, err := s.ledger.GetSecurityControl(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, control)
}

func (s *Server) linkControlEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EvidenceType string `json:"evidence_type"`
		SubjectType  string `json:"subject_type"`
		SubjectID    string `json:"subject_id"`
		ProductID    string `json:"product_id"`
		ReleaseID    string `json:"release_id"`
		Confidence   string `json:"confidence"`
		Notes        string `json:"notes"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		link, err := s.ledger.LinkControlEvidence(r.Context(), actor, r.PathValue("id"), app.LinkControlEvidenceInput{
			EvidenceType: req.EvidenceType,
			SubjectType:  req.SubjectType,
			SubjectID:    req.SubjectID,
			ProductID:    req.ProductID,
			ReleaseID:    req.ReleaseID,
			Confidence:   req.Confidence,
			Notes:        req.Notes,
		})
		return http.StatusCreated, link, err
	})
}

func (s *Server) listControlEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	links, err := s.ledger.ListControlEvidence(r.Context(), actor, r.URL.Query().Get("control_id"), r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, links)
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Slug string }
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		product, err := s.ledger.CreateProduct(r.Context(), actor, req.Name, req.Slug)
		return http.StatusCreated, product, err
	})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	products, err := s.ledger.ListProducts(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, products)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		project, err := s.ledger.CreateProject(r.Context(), actor, req.ProductID, req.Name)
		return http.StatusCreated, project, err
	})
}

func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.ledger.CreateRelease(r.Context(), actor, req.ProductID, req.Version)
		return http.StatusCreated, release, err
	})
}

func (s *Server) getRelease(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	release, err := s.ledger.GetRelease(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, release)
}

func (s *Server) freezeRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		release, err := s.ledger.FreezeRelease(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, release, err
	})
}

func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		release, err := s.ledger.ApproveRelease(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, release, err
	})
}

func (s *Server) createReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		Name        string   `json:"name"`
		BuildIDs    []string `json:"build_ids"`
		ArtifactIDs []string `json:"artifact_ids"`
		SBOMIDs     []string `json:"sbom_ids"`
		ScanIDs     []string `json:"scan_ids"`
		VEXIDs      []string `json:"vex_ids"`
		ContractIDs []string `json:"contract_ids"`
		BundleIDs   []string `json:"bundle_ids"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		candidate, err := s.ledger.CreateReleaseCandidate(r.Context(), actor, app.CreateReleaseCandidateInput{
			ReleaseID: req.ReleaseID, Name: req.Name, BuildIDs: req.BuildIDs, ArtifactIDs: req.ArtifactIDs,
			SBOMIDs: req.SBOMIDs, ScanIDs: req.ScanIDs, VEXIDs: req.VEXIDs, ContractIDs: req.ContractIDs, BundleIDs: req.BundleIDs,
		})
		return http.StatusCreated, candidate, err
	})
}

func (s *Server) listReleaseCandidates(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	candidates, err := s.ledger.ListReleaseCandidates(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, candidates)
}

func (s *Server) getReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	candidate, err := s.ledger.GetReleaseCandidate(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, candidate)
}

func (s *Server) promoteReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "promoted")
}

func (s *Server) rejectReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "rejected")
}

func (s *Server) transitionReleaseCandidate(w http.ResponseWriter, r *http.Request, state string) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		candidate, err := s.ledger.UpdateReleaseCandidateState(r.Context(), actor, r.PathValue("id"), state, req.Reason)
		return http.StatusOK, candidate, err
	})
}

func (s *Server) registerArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		MediaType string `json:"media_type"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		artifact, err := s.ledger.RegisterArtifact(r.Context(), actor, req.Name, req.MediaType, req.Digest, req.Size)
		return http.StatusCreated, artifact, err
	})
}

func (s *Server) registerContainerImage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID string `json:"artifact_id"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Digest     string `json:"digest"`
		Platform   string `json:"platform"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		image, err := s.ledger.RegisterContainerImage(r.Context(), actor, app.RegisterContainerImageInput{
			ArtifactID: req.ArtifactID, Repository: req.Repository, Tag: req.Tag, Digest: req.Digest, Platform: req.Platform,
		})
		return http.StatusCreated, image, err
	})
}

func (s *Server) createArtifactSignature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID       string          `json:"artifact_id"`
		Algorithm        string          `json:"algorithm"`
		KeyID            string          `json:"key_id"`
		Signature        string          `json:"signature"`
		Payload          json.RawMessage `json:"payload"`
		PayloadMediaType string          `json:"payload_media_type"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sig, err := s.ledger.CreateArtifactSignature(r.Context(), actor, app.CreateArtifactSignatureInput{
			ArtifactID: req.ArtifactID, Algorithm: req.Algorithm, KeyID: req.KeyID, Signature: req.Signature,
			RawPayload: req.Payload, PayloadMediaType: req.PayloadMediaType,
		})
		return http.StatusCreated, sig, err
	})
}

func (s *Server) getArtifactSignature(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	sig, err := s.ledger.GetArtifactSignature(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sig)
}

func (s *Server) verifyCosignSignature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RekorUUID           string `json:"rekor_uuid"`
		RekorLogIndex       string `json:"rekor_log_index"`
		CertificateIdentity string `json:"certificate_identity"`
		CertificateIssuer   string `json:"certificate_issuer"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		result, err := s.ledger.VerifyCosignSignature(r.Context(), actor, app.VerifyCosignInput{
			ArtifactSignatureID: r.PathValue("id"),
			RekorUUID:           req.RekorUUID,
			RekorLogIndex:       req.RekorLogIndex,
			CertificateIdentity: req.CertificateIdentity,
			CertificateIssuer:   req.CertificateIssuer,
		})
		return http.StatusOK, result, err
	})
}

func (s *Server) createBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID        string               `json:"project_id"`
		ReleaseID        string               `json:"release_id"`
		Provider         string               `json:"provider"`
		CommitSHA        string               `json:"commit_sha"`
		Repository       string               `json:"repository"`
		WorkflowRef      string               `json:"workflow_ref"`
		RunID            string               `json:"run_id"`
		RunAttempt       int                  `json:"run_attempt"`
		JobID            string               `json:"job_id"`
		GitHubActor      string               `json:"actor"`
		Ref              string               `json:"ref"`
		OIDCSubject      string               `json:"oidc_subject"`
		Status           string               `json:"status"`
		StartedAt        time.Time            `json:"started_at"`
		FinishedAt       *time.Time           `json:"finished_at"`
		ParametersHash   string               `json:"parameters_hash"`
		EnvironmentHash  string               `json:"environment_hash"`
		ProviderMetadata map[string]any       `json:"provider_metadata"`
		Outputs          []domain.BuildOutput `json:"outputs"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		build, err := s.ledger.CreateBuildRun(r.Context(), actor, app.CreateBuildRunInput{
			ProjectID:        req.ProjectID,
			ReleaseID:        req.ReleaseID,
			Provider:         req.Provider,
			CommitSHA:        req.CommitSHA,
			Repository:       req.Repository,
			WorkflowRef:      req.WorkflowRef,
			RunID:            req.RunID,
			RunAttempt:       req.RunAttempt,
			JobID:            req.JobID,
			GitHubActor:      req.GitHubActor,
			Ref:              req.Ref,
			OIDCSubject:      req.OIDCSubject,
			Status:           req.Status,
			StartedAt:        req.StartedAt,
			FinishedAt:       req.FinishedAt,
			ParametersHash:   req.ParametersHash,
			EnvironmentHash:  req.EnvironmentHash,
			ProviderMetadata: req.ProviderMetadata,
			Outputs:          req.Outputs,
		})
		return http.StatusCreated, build, err
	})
}

func (s *Server) getBuild(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	build, err := s.ledger.GetBuildRun(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, build)
}

func (s *Server) uploadBuildAttestation(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		attestation, err := s.ledger.UploadBuildAttestation(r.Context(), actor, r.PathValue("id"), body)
		return http.StatusCreated, attestation, err
	})
}

func (s *Server) verifyBuildAttestationSignature(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		result, err := s.ledger.VerifyDSSEAttestationSignature(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, result, err
	})
}

func (s *Server) createDSSETrustRoot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		root, err := s.ledger.CreateDSSETrustRoot(r.Context(), actor, app.CreateDSSETrustRootInput{Name: req.Name, KeyID: req.KeyID, Algorithm: req.Algorithm, PublicKey: req.PublicKey})
		return http.StatusCreated, root, err
	})
}

func (s *Server) createSourceRepository(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID     string `json:"project_id"`
		Provider      string `json:"provider"`
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		repo, err := s.ledger.CreateSourceRepository(r.Context(), actor, app.CreateRepositoryInput{
			ProjectID: req.ProjectID, Provider: req.Provider, FullName: req.FullName, CloneURL: req.CloneURL, DefaultBranch: req.DefaultBranch,
		})
		return http.StatusCreated, repo, err
	})
}

func (s *Server) listSourceRepositories(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	repos, err := s.ledger.ListSourceRepositories(r.Context(), actor, r.URL.Query().Get("project_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, repos)
}

func (s *Server) recordSourceCommit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID string    `json:"repository_id"`
		SHA          string    `json:"sha"`
		Author       string    `json:"author"`
		Message      string    `json:"message"`
		CommittedAt  time.Time `json:"committed_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		commit, err := s.ledger.RecordSourceCommit(r.Context(), actor, app.RecordCommitInput{
			RepositoryID: req.RepositoryID, SHA: req.SHA, Author: req.Author, Message: req.Message, CommittedAt: req.CommittedAt,
		})
		return http.StatusCreated, commit, err
	})
}

func (s *Server) upsertSourceBranch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Name           string `json:"name"`
		HeadCommitID   string `json:"head_commit_id"`
		Protected      bool   `json:"protected"`
		ProtectionHash string `json:"protection_hash"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		branch, err := s.ledger.UpsertSourceBranch(r.Context(), actor, app.UpsertBranchInput{
			RepositoryID: req.RepositoryID, Name: req.Name, HeadCommitID: req.HeadCommitID, Protected: req.Protected, ProtectionHash: req.ProtectionHash,
		})
		return http.StatusCreated, branch, err
	})
}

func (s *Server) recordPullRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Provider       string `json:"provider"`
		ProviderID     string `json:"provider_id"`
		Title          string `json:"title"`
		State          string `json:"state"`
		SourceBranch   string `json:"source_branch"`
		TargetBranch   string `json:"target_branch"`
		HeadCommitID   string `json:"head_commit_id"`
		ReviewDecision string `json:"review_decision"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pr, err := s.ledger.RecordPullRequest(r.Context(), actor, app.RecordPullRequestInput{
			RepositoryID: req.RepositoryID, Provider: req.Provider, ProviderID: req.ProviderID, Title: req.Title, State: req.State,
			SourceBranch: req.SourceBranch, TargetBranch: req.TargetBranch, HeadCommitID: req.HeadCommitID, ReviewDecision: req.ReviewDecision,
		})
		return http.StatusCreated, pr, err
	})
}

func (s *Server) uploadGitHubSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		result, err := s.ledger.UploadGitHubSourceSnapshot(r.Context(), actor, body)
		return http.StatusCreated, result, err
	})
}

func (s *Server) uploadGitLabSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		result, err := s.ledger.UploadGitLabSourceSnapshot(r.Context(), actor, body)
		return http.StatusCreated, result, err
	})
}

func (s *Server) createDeploymentEnvironment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		env, err := s.ledger.CreateDeploymentEnvironment(r.Context(), actor, app.CreateEnvironmentInput{ProductID: req.ProductID, Name: req.Name, Kind: req.Kind})
		return http.StatusCreated, env, err
	})
}

func (s *Server) listDeploymentEnvironments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	envs, err := s.ledger.ListDeploymentEnvironments(r.Context(), actor, r.URL.Query().Get("product_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, envs)
}

func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnvironmentID string     `json:"environment_id"`
		ReleaseID     string     `json:"release_id"`
		ArtifactIDs   []string   `json:"artifact_ids"`
		Status        string     `json:"status"`
		StartedAt     time.Time  `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
		RollbackOf    string     `json:"rollback_of"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		deployment, err := s.ledger.RecordDeployment(r.Context(), actor, app.RecordDeploymentInput{
			EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ArtifactIDs: req.ArtifactIDs,
			Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, RollbackOf: req.RollbackOf,
		})
		return http.StatusCreated, deployment, err
	})
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	deployments, err := s.ledger.ListDeployments(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("environment_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, deployments)
}

func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	deployment, err := s.ledger.GetDeployment(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, deployment)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string    `json:"product_id"`
		ReleaseID string    `json:"release_id"`
		Title     string    `json:"title"`
		Severity  string    `json:"severity"`
		OpenedAt  time.Time `json:"opened_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		incident, err := s.ledger.CreateIncident(r.Context(), actor, app.CreateIncidentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title, Severity: req.Severity, OpenedAt: req.OpenedAt})
		return http.StatusCreated, incident, err
	})
}

func (s *Server) recordIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventType  string    `json:"event_type"`
		Summary    string    `json:"summary"`
		EvidenceID string    `json:"evidence_id"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.ledger.RecordIncidentTimelineEvent(r.Context(), actor, r.PathValue("id"), app.RecordIncidentTimelineInput{EventType: req.EventType, Summary: req.Summary, EvidenceID: req.EvidenceID, OccurredAt: req.OccurredAt})
		return http.StatusCreated, event, err
	})
}

func (s *Server) createRemediationTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IncidentID string     `json:"incident_id"`
		ReleaseID  string     `json:"release_id"`
		Title      string     `json:"title"`
		Owner      string     `json:"owner"`
		DueAt      *time.Time `json:"due_at"`
		EvidenceID string     `json:"evidence_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		task, err := s.ledger.CreateRemediationTask(r.Context(), actor, app.CreateRemediationTaskInput{IncidentID: req.IncidentID, ReleaseID: req.ReleaseID, Title: req.Title, Owner: req.Owner, DueAt: req.DueAt, EvidenceID: req.EvidenceID})
		return http.StatusCreated, task, err
	})
}

func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.IncidentReport(r.Context(), actor, r.URL.Query().Get("incident_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadSecurityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Category   string          `json:"category"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.ledger.UploadSecurityScan(r.Context(), actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Category: req.Category, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadAPISecurityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.ledger.UploadAPISecurityScan(r.Context(), actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadManualSecurityDocument(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID    string          `json:"product_id"`
		ReleaseID    string          `json:"release_id"`
		DocumentType string          `json:"document_type"`
		Title        string          `json:"title"`
		Sensitivity  string          `json:"sensitivity"`
		MediaType    string          `json:"media_type"`
		Payload      json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		doc, err := s.ledger.UploadManualSecurityDocument(r.Context(), actor, app.UploadManualSecurityDocumentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, DocumentType: req.DocumentType, Title: req.Title, Sensitivity: req.Sensitivity, Raw: req.Payload, MediaType: req.MediaType})
		return http.StatusCreated, doc, err
	})
}

func (s *Server) createWaiver(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType  string    `json:"scope_type"`
		ScopeID    string    `json:"scope_id"`
		ControlID  string    `json:"control_id"`
		PolicyID   string    `json:"policy_id"`
		Owner      string    `json:"owner"`
		Risk       string    `json:"risk"`
		Reason     string    `json:"reason"`
		ExpiresAt  time.Time `json:"expires_at"`
		Supersedes string    `json:"supersedes"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		waiver, err := s.ledger.CreateWaiver(r.Context(), actor, app.CreateWaiverInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, ControlID: req.ControlID, PolicyID: req.PolicyID, Owner: req.Owner, Risk: req.Risk, Reason: req.Reason, ExpiresAt: req.ExpiresAt, Supersedes: req.Supersedes})
		return http.StatusCreated, waiver, err
	})
}

func (s *Server) approveWaiver(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		waiver, err := s.ledger.ApproveWaiver(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, waiver, err
	})
}

func (s *Server) createApproval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		Decision    string `json:"decision"`
		Reason      string `json:"reason"`
		EvidenceID  string `json:"evidence_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		approval, err := s.ledger.CreateApprovalRecord(r.Context(), actor, app.CreateApprovalInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Decision: req.Decision, Reason: req.Reason, EvidenceID: req.EvidenceID})
		return http.StatusCreated, approval, err
	})
}

func (s *Server) createRedactionProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		AllowedTypes   []string `json:"allowed_types"`
		ExcludedFields []string `json:"excluded_fields"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		profile, err := s.ledger.CreateRedactionProfile(r.Context(), actor, app.CreateRedactionProfileInput{Name: req.Name, Description: req.Description, AllowedTypes: req.AllowedTypes, ExcludedFields: req.ExcludedFields})
		return http.StatusCreated, profile, err
	})
}

func (s *Server) createCustomerPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID          string    `json:"product_id"`
		ReleaseID          string    `json:"release_id"`
		RedactionProfileID string    `json:"redaction_profile_id"`
		Title              string    `json:"title"`
		ExpiresAt          time.Time `json:"expires_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pkg, err := s.ledger.CreateCustomerSecurityPackage(r.Context(), actor, app.CreateCustomerPackageInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, RedactionProfileID: req.RedactionProfileID, Title: req.Title, ExpiresAt: req.ExpiresAt})
		return http.StatusCreated, pkg, err
	})
}

func (s *Server) getCustomerPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	pkg, err := s.ledger.AccessCustomerSecurityPackage(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, pkg)
}

func (s *Server) securityReviewPackageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.SecurityReviewPackageReport(r.Context(), actor, r.URL.Query().Get("package_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessHTMLPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CRAReadinessHTMLPackage(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		ReportType    string   `json:"report_type"`
		AllowedFields []string `json:"allowed_fields"`
		Template      string   `json:"template"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		tpl, err := s.ledger.CreateCustomReportTemplate(r.Context(), actor, app.CreateReportTemplateInput{Name: req.Name, Version: req.Version, ReportType: req.ReportType, AllowedFields: req.AllowedFields, Template: req.Template})
		return http.StatusCreated, tpl, err
	})
}

func (s *Server) renderReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		report, err := s.ledger.RenderCustomReport(r.Context(), actor, app.RenderReportInput{TemplateID: r.PathValue("id"), SubjectType: req.SubjectType, SubjectID: req.SubjectID})
		return http.StatusCreated, report, err
	})
}

func (s *Server) exportEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		bundle, err := s.ledger.ExportEvidenceBundle(r.Context(), actor, req.ReleaseID, req.EvidenceIDs)
		return http.StatusCreated, bundle, err
	})
}

func (s *Server) importEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req domain.EvidenceBundle
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.ImportEvidenceBundle(r.Context(), actor, req)
		return http.StatusCreated, record, err
	})
}

func (s *Server) uploadSPDXSBOM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.ledger.UploadSPDXSBOM(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) createSBOMDiff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseSBOMID   string `json:"base_sbom_id"`
		TargetSBOMID string `json:"target_sbom_id"`
		ReleaseID    string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.ledger.CreateSBOMDiff(r.Context(), actor, app.CreateSBOMDiffInput{BaseSBOMID: req.BaseSBOMID, TargetSBOMID: req.TargetSBOMID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) createEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID        string              `json:"product_id"`
		ProjectID        string              `json:"project_id"`
		ReleaseID        string              `json:"release_id"`
		Type             string              `json:"type"`
		Subtype          string              `json:"subtype"`
		Title            string              `json:"title"`
		SourceSystem     string              `json:"source_system"`
		SourceIdentity   map[string]any      `json:"source_identity"`
		CollectorID      string              `json:"collector_id"`
		ObservedAt       time.Time           `json:"observed_at"`
		PayloadRef       string              `json:"payload_ref"`
		PayloadHash      string              `json:"payload_hash"`
		PayloadMediaType string              `json:"payload_media_type"`
		PayloadSize      int64               `json:"payload_size"`
		SubjectRefs      []domain.SubjectRef `json:"subject_refs"`
		Metadata         map[string]any      `json:"metadata"`
		Tags             []string            `json:"tags"`
		Limitations      []string            `json:"limitations"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.CreateEvidence(r.Context(), actor, app.CreateEvidenceInput{
			ProductID: req.ProductID, ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, Type: req.Type, Subtype: req.Subtype, Title: req.Title,
			SourceSystem: req.SourceSystem, SourceIdentity: req.SourceIdentity, CollectorID: req.CollectorID, ObservedAt: req.ObservedAt,
			PayloadRef: req.PayloadRef, PayloadHash: req.PayloadHash, PayloadMediaType: req.PayloadMediaType, PayloadSize: req.PayloadSize,
			SubjectRefs: req.SubjectRefs, Metadata: req.Metadata, Tags: req.Tags, Limitations: req.Limitations,
		})
		return http.StatusCreated, item, err
	})
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	items, err := s.ledger.ListEvidence(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("type"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, items)
}

func (s *Server) searchEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	limit := 0
	if query.Get("limit") != "" {
		parsed, err := strconv.Atoi(query.Get("limit"))
		if err != nil || parsed < 0 {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		limit = parsed
	}
	createdAfter, err := parseOptionalRFC3339(query.Get("created_after"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	createdBefore, err := parseOptionalRFC3339(query.Get("created_before"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	items, err := s.ledger.SearchEvidence(r.Context(), actor, app.EvidenceSearchInput{
		ProductID:          query.Get("product_id"),
		ProjectID:          query.Get("project_id"),
		ReleaseID:          query.Get("release_id"),
		BuildID:            query.Get("build_id"),
		DeploymentID:       query.Get("deployment_id"),
		Type:               query.Get("type"),
		Subtype:            query.Get("subtype"),
		SourceSystem:       query.Get("source_system"),
		CollectorID:        query.Get("collector_id"),
		VerificationStatus: query.Get("verification_status"),
		SubjectType:        query.Get("subject_type"),
		SubjectID:          query.Get("subject_id"),
		Tag:                query.Get("tag"),
		CreatedAfter:       createdAfter,
		CreatedBefore:      createdBefore,
		Limit:              limit,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, items)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	item, err := s.ledger.GetEvidence(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, item)
}

func (s *Server) supersedeEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReplacementEvidenceID string `json:"replacement_evidence_id"`
		Reason                string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.SupersedeEvidence(r.Context(), actor, r.PathValue("id"), req.ReplacementEvidenceID, req.Reason)
		return http.StatusCreated, item, err
	})
}

func (s *Server) linkEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.LinkEvidence(r.Context(), actor, r.PathValue("id"), req.TargetType, req.TargetID)
		return http.StatusCreated, item, err
	})
}

func (s *Server) recordEvidenceLifecycleEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action        string         `json:"action"`
		Reason        string         `json:"reason"`
		Details       map[string]any `json:"details"`
		ReplacementID string         `json:"replacement_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.ledger.RecordEvidenceLifecycleEvent(r.Context(), actor, r.PathValue("id"), app.RecordEvidenceLifecycleInput{
			Action: req.Action, Reason: req.Reason, Details: req.Details, ReplacementID: req.ReplacementID,
		})
		return http.StatusCreated, event, err
	})
}

func (s *Server) listEvidenceLifecycleEvents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	events, err := s.ledger.ListEvidenceLifecycleEvents(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, events)
}

func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.ledger.UploadSBOM(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) getSBOM(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	sbom, err := s.ledger.GetSBOM(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sbom)
}

func (s *Server) uploadVEX(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.ledger.UploadVEX(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) getVEX(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	vex, err := s.ledger.GetVEXDocument(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, vex)
}

func (s *Server) uploadCycloneDXVEX(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.ledger.UploadCycloneDXVEX(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) uploadVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		scan, err := s.ledger.UploadVulnerabilityScan(r.Context(), actor, body)
		return http.StatusCreated, scan, err
	})
}

func (s *Server) getVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	scan, err := s.ledger.GetVulnerabilityScan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, scan)
}

func (s *Server) createVulnerabilityDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		decision, err := s.ledger.CreateVulnerabilityDecision(r.Context(), actor, r.PathValue("id"), app.CreateVulnerabilityDecisionInput{
			Status:          req.Status,
			Justification:   req.Justification,
			ImpactStatement: req.ImpactStatement,
			ActionStatement: req.ActionStatement,
		})
		return http.StatusCreated, decision, err
	})
}

func (s *Server) recordVulnerabilityWorkflow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.RecordVulnerabilityWorkflow(r.Context(), actor, app.RecordVulnerabilityWorkflowInput{FindingID: r.PathValue("id"), Action: req.Action, Reason: req.Reason})
		return http.StatusCreated, record, err
	})
}

func (s *Server) vulnerabilityPostureReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.VulnerabilityPostureReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string          `json:"product_id"`
		ReleaseID string          `json:"release_id"`
		Version   string          `json:"version"`
		Spec      json.RawMessage `json:"spec"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		contract, err := s.ledger.UploadOpenAPIContract(r.Context(), actor, req.ProductID, req.ReleaseID, req.Version, req.Spec)
		return http.StatusCreated, contract, err
	})
}

func (s *Server) getOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	contract, err := s.ledger.GetOpenAPIContract(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, contract)
}

func (s *Server) createOpenAPIDiff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseContractID   string `json:"base_contract_id"`
		TargetContractID string `json:"target_contract_id"`
		ReleaseID        string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.ledger.CreateContractDiff(r.Context(), actor, app.CreateContractDiffInput{BaseContractID: req.BaseContractID, TargetContractID: req.TargetContractID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.ledger.EvaluateRelease(r.Context(), actor, req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) createCustomPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string              `json:"name"`
		Version     string              `json:"version"`
		Description string              `json:"description"`
		Rules       []domain.PolicyRule `json:"rules"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		policy, err := s.ledger.CreateCustomPolicy(r.Context(), actor, app.CreateCustomPolicyInput{Name: req.Name, Version: req.Version, Description: req.Description, Rules: req.Rules})
		return http.StatusCreated, policy, err
	})
}

func (s *Server) evaluateCustomPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.ledger.EvaluateCustomPolicy(r.Context(), actor, r.PathValue("id"), req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) missingEvidenceReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.MissingEvidenceReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string    `json:"release_id"`
		FindingID string    `json:"finding_id"`
		ControlID string    `json:"control_id"`
		Reason    string    `json:"reason"`
		Owner     string    `json:"owner"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		exception, err := s.ledger.CreateException(r.Context(), actor, app.CreateExceptionInput{
			ReleaseID: req.ReleaseID,
			FindingID: req.FindingID,
			ControlID: req.ControlID,
			Reason:    req.Reason,
			Owner:     req.Owner,
			ExpiresAt: req.ExpiresAt,
		})
		return http.StatusCreated, exception, err
	})
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	exceptions, err := s.ledger.ListExceptions(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, exceptions)
}

func (s *Server) approveException(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		exception, err := s.ledger.ApproveException(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, exception, err
	})
}

func (s *Server) releaseReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.ReleaseReadinessReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) controlCoverageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.ControlCoverageReport(r.Context(), actor, app.ControlCoverageReportInput{
		FrameworkID: r.URL.Query().Get("framework_id"),
		ProductID:   r.URL.Query().Get("product_id"),
		ReleaseID:   r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CRAReadinessReport(r.Context(), actor, app.CRAReadinessReportInput{
		ProductID: r.URL.Query().Get("product_id"),
		ReleaseID: r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReleaseBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		bundle, err := s.ledger.CreateReleaseBundle(r.Context(), actor, req.ReleaseID)
		return http.StatusCreated, bundle, err
	})
}

func (s *Server) getReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle)
}

func (s *Server) getReleaseBundleManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle.Manifest)
}

func (s *Server) verifyReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifySubject(r.Context(), actor, "release_bundle", r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifySubject(r.Context(), actor, "audit_chain", "")
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listAuditLog(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var since *time.Time
	if value := strings.TrimSpace(r.URL.Query().Get("since")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		since = &parsed
	}
	limit := 0
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		limit = parsed
	}
	entries, err := s.ledger.ListAuditLog(r.Context(), actor, app.AuditLogFilter{
		SubjectType: r.URL.Query().Get("subject_type"),
		SubjectID:   r.URL.Query().Get("subject_id"),
		Since:       since,
		Limit:       limit,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, entries)
}

func (s *Server) createMerkleBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromSequence int64 `json:"from_sequence"`
		ToSequence   int64 `json:"to_sequence"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		batch, err := s.ledger.CreateMerkleBatch(r.Context(), actor, app.CreateMerkleBatchInput{FromSequence: req.FromSequence, ToSequence: req.ToSequence})
		return http.StatusCreated, batch, err
	})
}

func (s *Server) verifyMerkleBatch(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifyMerkleBatch(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) createTransparencyCheckpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchID     string `json:"batch_id"`
		Provider    string `json:"provider"`
		ExternalURL string `json:"external_url"`
		ExternalID  string `json:"external_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		checkpoint, err := s.ledger.CreateTransparencyCheckpoint(r.Context(), actor, app.CreateTransparencyCheckpointInput{BatchID: req.BatchID, Provider: req.Provider, ExternalURL: req.ExternalURL, ExternalID: req.ExternalID})
		return http.StatusCreated, checkpoint, err
	})
}

func (s *Server) createObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		ObjectPrefix  string `json:"object_prefix"`
		Mode          string `json:"mode"`
		RetentionDays int    `json:"retention_days"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		policy, err := s.ledger.CreateObjectRetentionPolicy(r.Context(), actor, app.CreateObjectRetentionPolicyInput{Name: req.Name, ObjectPrefix: req.ObjectPrefix, Mode: req.Mode, RetentionDays: req.RetentionDays})
		return http.StatusCreated, policy, err
	})
}

func (s *Server) verifyObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		policy, err := s.ledger.VerifyObjectRetentionPolicy(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, policy, err
	})
}

func (s *Server) generateBackupManifest(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		manifest, err := s.ledger.GenerateBackupManifest(r.Context(), actor)
		return http.StatusCreated, manifest, err
	})
}

func (s *Server) verifyBackupManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifyBackupManifest(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := s.ledger.ListSigningKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, keys)
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if len(bytes.TrimSpace(body)) > 0 {
			if err := decodeJSON(body, &req); err != nil {
				return 0, nil, err
			}
		}
		key, err := s.ledger.RotateSigningKey(r.Context(), actor, req.Reason)
		return http.StatusCreated, key, err
	})
}

func (s *Server) revokeSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if len(bytes.TrimSpace(body)) > 0 {
			if err := decodeJSON(body, &req); err != nil {
				return 0, nil, err
			}
		}
		key, err := s.ledger.RevokeSigningKey(r.Context(), actor, r.PathValue("id"), req.Reason)
		return http.StatusOK, key, err
	})
}

func (s *Server) createSigningProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		KeyRef    string `json:"key_ref"`
		Encrypted bool   `json:"encrypted"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		provider, err := s.ledger.CreateSigningProvider(r.Context(), actor, app.CreateSigningProviderInput{Name: req.Name, Type: req.Type, KeyRef: req.KeyRef, Encrypted: req.Encrypted})
		return http.StatusCreated, provider, err
	})
}

func (s *Server) createCommercialCollector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Provider      string   `json:"provider"`
		Version       string   `json:"version"`
		ManifestHash  string   `json:"manifest_hash"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		definition, err := s.ledger.CreateCommercialCollectorDefinition(r.Context(), actor, app.CreateCommercialCollectorInput{
			Name:          req.Name,
			Provider:      req.Provider,
			Version:       req.Version,
			ManifestHash:  req.ManifestHash,
			AllowedScopes: req.AllowedScopes,
		})
		return http.StatusCreated, definition, err
	})
}

func (s *Server) listCommercialCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	definitions, err := s.ledger.ListCommercialCollectorDefinitions(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, definitions)
}

func (s *Server) verifySubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		result, err := s.ledger.VerifySubject(r.Context(), actor, req.SubjectType, req.SubjectID)
		return http.StatusOK, result, err
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		key, secret, err := s.ledger.CreateAPIKey(r.Context(), actor, req.Name, req.Scopes, req.ExpiresAt)
		return http.StatusCreated, map[string]any{"api_key": key, "secret": secret}, err
	})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := s.ledger.ListAPIKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, keys)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, run func(domain.Actor, []byte) (int, any, error)) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status, response, err := s.ledger.WithIdempotency(r.Context(), actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), body, func() (int, any, error) {
		return run(actor, body)
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if r.Header.Get("Idempotency-Key") != "" {
		w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	}
	writeData(w, status, response)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	actor, err := s.ledger.Authenticate(r.Context(), strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if err != nil {
		writeProblem(w, r, err)
		return domain.Actor{}, false
	}
	return actor, true
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return nil, app.ErrValidation
	}
	if len(body) > maxJSONBody {
		return nil, app.ErrValidation
	}
	return body, nil
}

func decodeJSON(body []byte, out any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		trimmed = []byte(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return app.ErrValidation
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return app.ErrValidation
	}
	return nil
}

func parseOptionalRFC3339(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, app.ErrValidation
	}
	return parsed, nil
}

func writeData(w http.ResponseWriter, status int, data any) {
	httpx.WriteJSON(w, status, map[string]any{"data": data, "meta": map[string]string{"api_version": "v1"}})
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	status := app.StatusCode(err)
	requestID := requestIDFromRequest(r)
	problem := httpx.Problem{
		Type:   "https://evydence.local/problems/" + strings.ToLower(strings.ReplaceAll(app.ProblemCode(err), "_", "-")),
		Title:  http.StatusText(status),
		Detail: app.SafeErrorDetail(err),
		Ext: map[string]any{
			"code":       app.ProblemCode(err),
			"request_id": requestID,
		},
	}
	if r != nil {
		problem.Instance = r.URL.Path
	}
	httpx.WriteProblem(w, status, problem)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
		if !safeRequestID(requestID) {
			requestID = newRequestID()
		}
		r.Header.Set(requestIDHeader, requestID)
		w.Header().Set(requestIDHeader, requestID)
		next.ServeHTTP(w, r)
	})
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return newRequestID()
	}
	requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
	if safeRequestID(requestID) {
		return requestID
	}
	return newRequestID()
}

func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(buf[:])
}

func safeRequestID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type serveMuxRouter struct {
	mux *http.ServeMux
}

func (r *serveMuxRouter) Get(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("GET "+pattern, h)
}

func (r *serveMuxRouter) Post(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("POST "+pattern, h)
}

func (r *serveMuxRouter) Put(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PUT "+pattern, h)
}

func (r *serveMuxRouter) Delete(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("DELETE "+pattern, h)
}

func (r *serveMuxRouter) Patch(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PATCH "+pattern, h)
}

func op(id, method, path, summary string, scopes []string) specs.Operation {
	operation := specs.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Tags:        []string{"evydence"},
		Responses: map[int]specs.Response{
			200: {Description: "OK"},
			201: {Description: "Created"},
			400: {Description: "Bad request"},
			401: {Description: "Unauthorized"},
			403: {Description: "Forbidden"},
			404: {Description: "Not found"},
			409: {Description: "Conflict"},
			422: {Description: "Verification failed"},
		},
	}
	if len(scopes) > 0 {
		operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
		operation.Scopes = scopes
	}
	if method == http.MethodPost {
		operation.Extensions = idempotent.OperationExtensions(true)
	}
	return operation
}
