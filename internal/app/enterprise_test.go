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
