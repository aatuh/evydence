package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestEnterpriseIdentityRBACSSOAndAdminSnapshot(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("organization: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "Security@Example.test", DisplayName: "Security"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if user.Email != "security@example.test" {
		t.Fatalf("email not normalized: %s", user.Email)
	}
	binding, err := ledger.CreateRoleBinding(ctx, actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: actor.TenantID})
	if err != nil {
		t.Fatalf("role binding: %v", err)
	}
	if binding.Role != "security_engineer" {
		t.Fatalf("binding = %#v", binding)
	}
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "Okta", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", RoleMapping: map[string]string{"security": "security_engineer"}})
	if err != nil {
		t.Fatalf("sso provider: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "sub-1", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("identity link: %v", err)
	}
	session, secret, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("sso session: %v", err)
	}
	if secret == "" || session.Hash != "" {
		t.Fatalf("session secret/hash leakage session=%#v secret=%q", session, secret)
	}
	sessionActor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("session auth: %v", err)
	}
	if sessionActor.UserID != user.ID || !sessionActor.HasScope(ScopeEvidenceWrite) || sessionActor.HasScope(ScopeIdentityAdmin) {
		t.Fatalf("session actor scopes = %#v", sessionActor)
	}
	if _, err := ledger.RevokeSSOSession(ctx, actor, session.ID); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, err := ledger.Authenticate(ctx, secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session auth err=%v, want unauthorized", err)
	}
	snapshot, err := ledger.InstanceAdminSnapshot(ctx, actor)
	if err != nil {
		t.Fatalf("instance snapshot: %v", err)
	}
	if snapshot.TenantCount != 1 || snapshot.ResourceCounts["users"] != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if _, err := ledger.DeactivateUser(ctx, actor, user.ID); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
}

func TestCustomerPortalRetentionQuestionnairesAndCommercialCollectors(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	item, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "sbom", Title: "SBOM", PayloadHash: sampleDigest("sbom")})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"sbom"}})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Customer", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	access, token, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: pkg.ID, CustomerName: "ACME", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("portal access: %v", err)
	}
	if token == "" || access.Hash != "" {
		t.Fatalf("portal token/hash leakage access=%#v token=%q", access, token)
	}
	portalPkg, err := ledger.AccessCustomerPortalPackage(ctx, token)
	if err != nil {
		t.Fatalf("portal package: %v", err)
	}
	if portalPkg.ID != pkg.ID {
		t.Fatalf("portal package id = %s want %s", portalPkg.ID, pkg.ID)
	}
	badToken := token[:len(token)-1] + "x"
	if badToken == token {
		badToken = token[:len(token)-1] + "y"
	}
	if _, err := ledger.AccessCustomerPortalPackage(ctx, badToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad portal token err=%v, want unauthorized", err)
	}
	entries, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{SubjectType: "customer_portal_access", SubjectID: access.ID, Limit: 10})
	if err != nil {
		t.Fatalf("portal audit log: %v", err)
	}
	foundFailedAccess := false
	for _, entry := range entries {
		if entry.EntryType == "customer_portal_package.access_failed" && entry.ActorID == "unverified" {
			foundFailedAccess = true
		}
		if entry.ActorID == badToken || entry.PayloadHash == badToken {
			t.Fatalf("portal audit leaked token: %#v", entry)
		}
	}
	if !foundFailedAccess {
		t.Fatalf("missing failed portal access audit entry: %#v", entries)
	}
	metrics, err := ledger.Metrics(ctx, actor)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if got := metrics["customer_portal_failed_access_count"]; got != 1 {
		t.Fatalf("portal failed access metric = %#v, want 1", got)
	}
	if _, err := ledger.CreateLegalHold(ctx, actor, CreateLegalHoldInput{ScopeType: "release", ScopeID: release.ID, Reason: "customer dispute", Owner: "legal"}); err != nil {
		t.Fatalf("legal hold: %v", err)
	}
	if _, err := ledger.CreateRetentionOverride(ctx, actor, CreateRetentionOverrideInput{ScopeType: "evidence", ScopeID: item.ID, RetentionUntil: fixedNow().Add(24 * time.Hour), Reason: "extended review", Owner: "security"}); err != nil {
		t.Fatalf("retention override: %v", err)
	}
	report, err := ledger.RetentionReport(ctx, actor, "release", release.ID)
	if err != nil {
		t.Fatalf("retention report: %v", err)
	}
	if len(report.LegalHolds) != 1 {
		t.Fatalf("retention report = %#v", report)
	}
	template, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Do you have an SBOM?", EvidenceType: "sbom"}}})
	if err != nil {
		t.Fatalf("questionnaire template: %v", err)
	}
	qpkg, err := ledger.CreateQuestionnairePackage(ctx, actor, CreateQuestionnairePackageInput{TemplateID: template.ID, PackageID: pkg.ID, ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("questionnaire package: %v", err)
	}
	if len(qpkg.Responses) != 1 || len(qpkg.Responses[0].EvidenceIDs) != 1 {
		t.Fatalf("questionnaire package = %#v", qpkg)
	}
	def, err := ledger.CreateCommercialCollectorDefinition(ctx, actor, CreateCommercialCollectorInput{Name: "jira", Provider: "jira", Version: "1.0.0", ManifestHash: sampleDigest("manifest"), AllowedScopes: []string{ScopeEvidenceWrite}})
	if err != nil {
		t.Fatalf("commercial collector: %v", err)
	}
	if defs, err := ledger.ListCommercialCollectorDefinitions(ctx, actor); err != nil || len(defs) != 1 || defs[0].ID != def.ID {
		t.Fatalf("commercial collector list=%#v err=%v", defs, err)
	}
	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("auth other: %v", err)
	}
	if _, _, err := ledger.CreateCustomerPortalAccess(ctx, other, CreateCustomerPortalAccessInput{PackageID: pkg.ID, CustomerName: "bad", ExpiresAt: fixedNow().Add(time.Hour)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant portal err=%v, want not found", err)
	}
}

func TestHumanSSOSessionRoleBindingsAreResourceScoped(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	productA, err := ledger.CreateProduct(ctx, admin, "A", "a")
	if err != nil {
		t.Fatalf("product A: %v", err)
	}
	releaseA, err := ledger.CreateRelease(ctx, admin, productA.ID, "1")
	if err != nil {
		t.Fatalf("release A: %v", err)
	}
	productB, err := ledger.CreateProduct(ctx, admin, "B", "b")
	if err != nil {
		t.Fatalf("product B: %v", err)
	}
	releaseB, err := ledger.CreateRelease(ctx, admin, productB.ID, "1")
	if err != nil {
		t.Fatalf("release B: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, admin, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, admin, CreateUserInput{OrganizationID: org.ID, Email: "release@example.test", DisplayName: "Release"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, admin, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "release_manager", ResourceType: "product", ResourceID: productA.ID}); err != nil {
		t.Fatalf("role binding: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, admin, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	session, sessionSecret, err := ledger.CreateSSOSession(ctx, admin, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	scoped, err := ledger.Authenticate(ctx, sessionSecret)
	if err != nil {
		t.Fatalf("session auth: %v", err)
	}
	if scoped.UserID != user.ID || len(scoped.ResourceGrants) != 1 || scoped.ResourceGrants[0].ResourceID != productA.ID {
		t.Fatalf("scoped actor = %#v session=%#v", scoped, session)
	}
	products, err := ledger.ListProducts(ctx, scoped)
	if err != nil {
		t.Fatalf("list products: %v", err)
	}
	if len(products) != 1 || products[0].ID != productA.ID {
		t.Fatalf("scoped products = %#v", products)
	}
	if _, err := ledger.GetRelease(ctx, scoped, releaseA.ID); err != nil {
		t.Fatalf("get allowed release: %v", err)
	}
	if _, err := ledger.GetRelease(ctx, scoped, releaseB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get foreign product release err=%v, want forbidden", err)
	}
	if _, err := ledger.CreateRelease(ctx, scoped, productA.ID, "2"); err != nil {
		t.Fatalf("create scoped release: %v", err)
	}
	if _, err := ledger.CreateRelease(ctx, scoped, productB.ID, "2"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("create foreign product release err=%v, want forbidden", err)
	}
	if _, err := ledger.CreateEvidence(ctx, scoped, CreateEvidenceInput{ProductID: productA.ID, ReleaseID: releaseA.ID, Type: "build", Title: "Build", PayloadHash: sampleDigest("allowed")}); err != nil {
		t.Fatalf("create scoped evidence: %v", err)
	}
	if _, err := ledger.CreateEvidence(ctx, scoped, CreateEvidenceInput{ProductID: productB.ID, ReleaseID: releaseB.ID, Type: "build", Title: "Build", PayloadHash: sampleDigest("denied")}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("create foreign evidence err=%v, want forbidden", err)
	}
	if _, err := ledger.MissingEvidenceReport(ctx, scoped, releaseB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign report err=%v, want forbidden", err)
	}

	profile, err := ledger.CreateRedactionProfile(ctx, admin, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"build"}})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pkgA, err := ledger.CreateCustomerSecurityPackage(ctx, admin, CreateCustomerPackageInput{ProductID: productA.ID, ReleaseID: releaseA.ID, RedactionProfileID: profile.ID, Title: "A package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package A: %v", err)
	}
	pkgB, err := ledger.CreateCustomerSecurityPackage(ctx, admin, CreateCustomerPackageInput{ProductID: productB.ID, ReleaseID: releaseB.ID, RedactionProfileID: profile.ID, Title: "B package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package B: %v", err)
	}
	verifier, err := ledger.CreateUser(ctx, admin, CreateUserInput{OrganizationID: org.ID, Email: "verifier@example.test", DisplayName: "Verifier"})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, admin, CreateRoleBindingInput{SubjectType: "user", SubjectID: verifier.ID, Role: "customer_verifier", ResourceType: "customer_security_package", ResourceID: pkgA.ID}); err != nil {
		t.Fatalf("verifier role: %v", err)
	}
	verifierSession, verifierSecret, err := ledger.CreateSSOSession(ctx, admin, CreateSSOSessionInput{UserID: verifier.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("verifier session: %v", err)
	}
	_ = verifierSession
	verifierActor, err := ledger.Authenticate(ctx, verifierSecret)
	if err != nil {
		t.Fatalf("verifier auth: %v", err)
	}
	if _, err := ledger.AccessCustomerSecurityPackage(ctx, verifierActor, pkgA.ID); err != nil {
		t.Fatalf("access scoped package: %v", err)
	}
	if _, err := ledger.AccessCustomerSecurityPackage(ctx, verifierActor, pkgB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("access foreign package err=%v, want forbidden", err)
	}
	if _, err := ledger.SecurityReviewPackageReport(ctx, verifierActor, pkgB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign package report err=%v, want forbidden", err)
	}
}

func TestHumanSSOSessionResourceScopeCoversWorkflowFamilies(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	productA, err := ledger.CreateProduct(ctx, admin, "A", "a")
	if err != nil {
		t.Fatalf("product A: %v", err)
	}
	releaseA, err := ledger.CreateRelease(ctx, admin, productA.ID, "1")
	if err != nil {
		t.Fatalf("release A: %v", err)
	}
	projectA, err := ledger.CreateProject(ctx, admin, productA.ID, "api")
	if err != nil {
		t.Fatalf("project A: %v", err)
	}
	artifactA, err := ledger.RegisterArtifact(ctx, admin, "api", "application/octet-stream", sampleDigest("artifact-a"), 10)
	if err != nil {
		t.Fatalf("artifact A: %v", err)
	}
	productB, err := ledger.CreateProduct(ctx, admin, "B", "b")
	if err != nil {
		t.Fatalf("product B: %v", err)
	}
	releaseB, err := ledger.CreateRelease(ctx, admin, productB.ID, "1")
	if err != nil {
		t.Fatalf("release B: %v", err)
	}
	projectB, err := ledger.CreateProject(ctx, admin, productB.ID, "api")
	if err != nil {
		t.Fatalf("project B: %v", err)
	}
	artifactB, err := ledger.RegisterArtifact(ctx, admin, "api-b", "application/octet-stream", sampleDigest("artifact-b"), 10)
	if err != nil {
		t.Fatalf("artifact B: %v", err)
	}

	framework, err := ledger.CreateControlFramework(ctx, admin, CreateControlFrameworkInput{Name: "Controls", Version: "1"})
	if err != nil {
		t.Fatalf("framework: %v", err)
	}
	control, err := ledger.CreateSecurityControl(ctx, admin, CreateSecurityControlInput{FrameworkID: framework.ID, Code: "EVD-1", Title: "Evidence", Objective: "Collect evidence", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", Required: true}}})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	buildA, err := ledger.CreateBuildRun(ctx, admin, CreateBuildRunInput{ProjectID: projectA.ID, ReleaseID: releaseA.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifactA.ID, Digest: artifactA.Digest}}})
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	buildB, err := ledger.CreateBuildRun(ctx, admin, CreateBuildRunInput{ProjectID: projectB.ID, ReleaseID: releaseB.ID, Provider: "generic_ci", CommitSHA: "1123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifactB.ID, Digest: artifactB.Digest}}})
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	incidentA, err := ledger.CreateIncident(ctx, admin, CreateIncidentInput{ProductID: productA.ID, ReleaseID: releaseA.ID, Title: "incident A", Severity: "high"})
	if err != nil {
		t.Fatalf("incident A: %v", err)
	}
	incidentB, err := ledger.CreateIncident(ctx, admin, CreateIncidentInput{ProductID: productB.ID, ReleaseID: releaseB.ID, Title: "incident B", Severity: "high"})
	if err != nil {
		t.Fatalf("incident B: %v", err)
	}
	envA, err := ledger.CreateDeploymentEnvironment(ctx, admin, CreateEnvironmentInput{ProductID: productA.ID, Name: "prod-a", Kind: "production"})
	if err != nil {
		t.Fatalf("env A: %v", err)
	}
	envB, err := ledger.CreateDeploymentEnvironment(ctx, admin, CreateEnvironmentInput{ProductID: productB.ID, Name: "prod-b", Kind: "production"})
	if err != nil {
		t.Fatalf("env B: %v", err)
	}
	depA, err := ledger.RecordDeployment(ctx, admin, RecordDeploymentInput{EnvironmentID: envA.ID, ReleaseID: releaseA.ID, ArtifactIDs: []string{artifactA.ID}, Status: deploymentStatusSucceeded, StartedAt: fixedNow()})
	if err != nil {
		t.Fatalf("deployment A: %v", err)
	}
	depB, err := ledger.RecordDeployment(ctx, admin, RecordDeploymentInput{EnvironmentID: envB.ID, ReleaseID: releaseB.ID, ArtifactIDs: []string{artifactB.ID}, Status: deploymentStatusSucceeded, StartedAt: fixedNow()})
	if err != nil {
		t.Fatalf("deployment B: %v", err)
	}
	repoA, err := ledger.CreateSourceRepository(ctx, admin, CreateRepositoryInput{ProjectID: projectA.ID, Provider: "github", FullName: "org/a"})
	if err != nil {
		t.Fatalf("repo A: %v", err)
	}
	repoB, err := ledger.CreateSourceRepository(ctx, admin, CreateRepositoryInput{ProjectID: projectB.ID, Provider: "github", FullName: "org/b"})
	if err != nil {
		t.Fatalf("repo B: %v", err)
	}

	org, err := ledger.CreateOrganization(ctx, admin, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, admin, CreateUserInput{OrganizationID: org.ID, Email: "scoped@example.test", DisplayName: "Scoped"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, admin, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "tenant_admin", ResourceType: "product", ResourceID: productA.ID}); err != nil {
		t.Fatalf("role binding: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, admin, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	_, sessionSecret, err := ledger.CreateSSOSession(ctx, admin, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	scoped, err := ledger.Authenticate(ctx, sessionSecret)
	if err != nil {
		t.Fatalf("scoped auth: %v", err)
	}

	if _, err := ledger.GetBuildRun(ctx, scoped, buildA.ID); err != nil {
		t.Fatalf("get allowed build: %v", err)
	}
	if _, err := ledger.GetBuildRun(ctx, scoped, buildB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get foreign build err=%v, want forbidden", err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, scoped, control.ID, LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "build", SubjectID: buildA.ID, ProductID: productA.ID, ReleaseID: releaseA.ID, Confidence: confidenceHigh}); err != nil {
		t.Fatalf("link allowed control evidence: %v", err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, scoped, control.ID, LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "build", SubjectID: buildB.ID, ProductID: productB.ID, ReleaseID: releaseB.ID, Confidence: confidenceHigh}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("link foreign control evidence err=%v, want forbidden", err)
	}
	if _, err := ledger.IncidentReport(ctx, scoped, incidentA.ID); err != nil {
		t.Fatalf("incident report A: %v", err)
	}
	if _, err := ledger.IncidentReport(ctx, scoped, incidentB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("incident report B err=%v, want forbidden", err)
	}
	if _, err := ledger.UploadSecurityScan(ctx, scoped, UploadSecurityScanInput{ProductID: productB.ID, ReleaseID: releaseB.ID, Category: "secret_scan", Format: "generic", Scanner: "scan", TargetRef: "target", Raw: []byte(`{"findings":[]}`)}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign security scan err=%v, want forbidden", err)
	}
	if _, err := ledger.GetDeployment(ctx, scoped, depA.ID); err != nil {
		t.Fatalf("get deployment A: %v", err)
	}
	if _, err := ledger.GetDeployment(ctx, scoped, depB.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get deployment B err=%v, want forbidden", err)
	}
	repos, err := ledger.ListSourceRepositories(ctx, scoped, "")
	if err != nil {
		t.Fatalf("list repos: %v", err)
	}
	if len(repos) != 1 || repos[0].ID != repoA.ID {
		t.Fatalf("scoped repos=%#v want only %s; foreign repo was %s", repos, repoA.ID, repoB.ID)
	}
	if _, err := ledger.RecordSourceCommit(ctx, scoped, RecordCommitInput{RepositoryID: repoB.ID, SHA: "2123456789abcdef0123456789abcdef01234567", CommittedAt: fixedNow()}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign source commit err=%v, want forbidden", err)
	}
	deployments, err := ledger.ListDeployments(ctx, scoped, "", "")
	if err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	if len(deployments) != 1 || deployments[0].ID != depA.ID {
		t.Fatalf("scoped deployments=%#v want only %s", deployments, depA.ID)
	}
}
