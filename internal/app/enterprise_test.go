package app

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestEnterpriseIdentityRBACSSOAndAdminSnapshot(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*", ScopeInstanceAdmin})
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

func TestSAMLProviderIdentityVerificationUsesConfiguredCertificate(t *testing.T) {
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
	privateKey, certPEM := samlTestCertificate(t)
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{
		Name:                    "SAML",
		Type:                    "saml",
		Issuer:                  "https://saml-idp.example.test",
		ClientID:                "saml-client",
		SAMLSigningCertificates: []string{certPEM},
	})
	if err != nil {
		t.Fatalf("saml provider: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "SAML Example", Slug: "saml-example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "saml@example.test", DisplayName: "SAML User"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "saml-sub", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("identity link: %v", err)
	}
	assertion := signedTestSAMLAssertion(t, privateKey, "https://saml-idp.example.test", "saml-client", "saml-sub", fixedNow().Add(-time.Minute), fixedNow().Add(time.Hour))
	verification, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "saml", ProviderID: provider.ID, Subject: "saml-sub", SAMLAssertion: assertion})
	if err != nil {
		t.Fatalf("provider verification: %v", err)
	}
	if verification.Result != "passed" || !hasVerifyCheck(verification.Checks, "saml_assertion_signature", "passed") {
		t.Fatalf("verification = %#v", verification)
	}
	badAssertion := strings.Replace(assertion, "saml-sub", "other-sub", 1)
	failed, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "saml", ProviderID: provider.ID, Subject: "saml-sub", SAMLAssertion: badAssertion})
	if !errors.Is(err, ErrVerificationFailed) || failed.Result != "failed" {
		t.Fatalf("bad assertion verification = %#v err=%v", failed, err)
	}
	for _, check := range failed.Checks {
		if strings.Contains(check.Detail, badAssertion) {
			t.Fatalf("verification leaked assertion in check detail: %#v", failed)
		}
	}
}

func TestOIDCProviderIdentityVerificationSupportsRS256JWKS(t *testing.T) {
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": "rsa-1",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndianExponent(privateKey.E)),
	}}}
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC RSA", Type: "oidc", Issuer: "https://rsa-idp.example.test", ClientID: "rsa-client"})
	if err != nil {
		t.Fatalf("sso provider: %v", err)
	}
	provider, err = ledger.UpdateSSOProviderTrustMaterial(ctx, actor, provider.ID, UpdateSSOProviderTrustMaterialInput{JWKS: jwks})
	if err != nil {
		t.Fatalf("update sso trust material: %v", err)
	}
	if provider.TrustMaterialUpdatedAt == nil || len(provider.JWKS) == 0 {
		t.Fatalf("provider trust material = %#v", provider)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "RSA Example", Slug: "rsa-example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "rsa@example.test", DisplayName: "RSA User"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "rsa-sub", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("identity link: %v", err)
	}
	idToken := signedTestRSAIDToken(t, privateKey, "rsa-1", map[string]any{
		"iss":            "https://rsa-idp.example.test",
		"aud":            []string{"other", "rsa-client"},
		"sub":            "rsa-sub",
		"email":          user.Email,
		"email_verified": true,
		"exp":            fixedNow().Add(time.Hour).Unix(),
	})
	verification, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "rsa-sub", IDToken: idToken})
	if err != nil {
		t.Fatalf("provider verification: %v", err)
	}
	if verification.Result != "passed" {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestOIDCProviderIdentityVerificationUsesStaticJWKS(t *testing.T) {
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
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "kid-1", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(pub)}}}
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", JWKS: jwks})
	if err != nil {
		t.Fatalf("sso provider: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Example", Slug: "example-oidc"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "oidc@example.test", DisplayName: "OIDC User"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "sub-1", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("identity link: %v", err)
	}
	idToken := signedTestIDToken(t, priv, "kid-1", map[string]any{
		"iss":            "https://idp.example.test",
		"aud":            "client",
		"sub":            "sub-1",
		"email":          user.Email,
		"email_verified": true,
		"exp":            fixedNow().Add(time.Hour).Unix(),
		"nbf":            fixedNow().Add(-time.Minute).Unix(),
	})
	verification, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "sub-1", IDToken: idToken})
	if err != nil {
		t.Fatalf("provider verification: %v", err)
	}
	if verification.Result != "passed" || len(verification.Checks) < 5 {
		t.Fatalf("verification = %#v", verification)
	}
	badAudience := signedTestIDToken(t, priv, "kid-1", map[string]any{
		"iss": "https://idp.example.test", "aud": "other-client", "sub": "sub-1", "email": user.Email, "email_verified": true, "exp": fixedNow().Add(time.Hour).Unix(),
	})
	failed, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "sub-1", IDToken: badAudience})
	if !errors.Is(err, ErrVerificationFailed) || failed.Result != "failed" {
		t.Fatalf("bad audience verification = %#v err=%v", failed, err)
	}
	if strings.Contains(failed.Checks[0].Detail, badAudience) {
		t.Fatalf("verification leaked token in check detail: %#v", failed)
	}
}

func TestInstanceAdminRequiresExplicitScope(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, tenantAdminSecret, err := ledger.BootstrapTenant(ctx, "Tenant", "tenant-admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant admin: %v", err)
	}
	tenantAdmin, err := ledger.Authenticate(ctx, tenantAdminSecret)
	if err != nil {
		t.Fatalf("tenant admin auth: %v", err)
	}
	if _, err := ledger.InstanceAdminSnapshot(ctx, tenantAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant wildcard snapshot err=%v, want forbidden", err)
	}
	if _, err := ledger.CreateProduct(ctx, tenantAdmin, "Tenant Product", "tenant-product"); err != nil {
		t.Fatalf("tenant admin should still create tenant resources: %v", err)
	}
	if _, _, err := ledger.CreateAPIKey(ctx, tenantAdmin, "instance-escalation", []string{ScopeInstanceAdmin}, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant admin instance key creation err=%v, want forbidden", err)
	}

	_, _, instanceSecret, err := ledger.BootstrapTenant(ctx, "Instance Tenant", "instance-admin", []string{"*", ScopeInstanceAdmin})
	if err != nil {
		t.Fatalf("bootstrap instance admin: %v", err)
	}
	instanceAdmin, err := ledger.Authenticate(ctx, instanceSecret)
	if err != nil {
		t.Fatalf("instance admin auth: %v", err)
	}
	if _, err := ledger.InstanceAdminSnapshot(ctx, instanceAdmin); err != nil {
		t.Fatalf("explicit instance admin snapshot: %v", err)
	}
	_, instanceKeySecret, err := ledger.CreateAPIKey(ctx, instanceAdmin, "instance-read", []string{ScopeInstanceAdmin}, nil)
	if err != nil {
		t.Fatalf("explicit instance key creation: %v", err)
	}
	instanceKeyActor, err := ledger.Authenticate(ctx, instanceKeySecret)
	if err != nil {
		t.Fatalf("instance key auth: %v", err)
	}
	if _, err := ledger.InstanceAdminSnapshot(ctx, instanceKeyActor); err != nil {
		t.Fatalf("instance key snapshot: %v", err)
	}

	org, err := ledger.CreateOrganization(ctx, tenantAdmin, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, tenantAdmin, CreateUserInput{OrganizationID: org.ID, Email: "admin@example.test", DisplayName: "Admin"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, tenantAdmin, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "tenant_admin", ResourceType: "tenant", ResourceID: tenantAdmin.TenantID}); err != nil {
		t.Fatalf("role binding: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, tenantAdmin, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	_, sessionSecret, err := ledger.CreateSSOSession(ctx, tenantAdmin, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	sessionActor, err := ledger.Authenticate(ctx, sessionSecret)
	if err != nil {
		t.Fatalf("session auth: %v", err)
	}
	if _, err := ledger.InstanceAdminSnapshot(ctx, sessionActor); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant-admin SSO snapshot err=%v, want forbidden", err)
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
	badToken := mutateTokenSuffix(token)
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

func TestCustomerPortalAccessRevokesAfterRepeatedFailedAttempts(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
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
	badToken := mutateTokenSuffix(token)
	for i := 0; i < customerPortalFailedAccessLimit; i++ {
		if _, err := ledger.AccessCustomerPortalPackage(ctx, badToken); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("bad portal token attempt %d err=%v, want unauthorized", i+1, err)
		}
	}
	if _, err := ledger.AccessCustomerPortalPackage(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked portal token err=%v, want unauthorized", err)
	}
	entries, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{SubjectType: "customer_portal_access", SubjectID: access.ID, Limit: 20})
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	var failures, revocations int
	for _, entry := range entries {
		switch entry.EntryType {
		case "customer_portal_package.access_failed":
			failures++
		case "customer_portal_access.revoked_after_failed_access":
			revocations++
		}
		if entry.ActorID == badToken || entry.PayloadHash == badToken {
			t.Fatalf("portal audit leaked token: %#v", entry)
		}
	}
	if failures != customerPortalFailedAccessLimit || revocations != 1 {
		t.Fatalf("audit entries failures=%d revocations=%d", failures, revocations)
	}
	metrics, err := ledger.Metrics(ctx, actor)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if metrics["customer_portal_failed_access_count"] != customerPortalFailedAccessLimit || metrics["customer_portal_revoked_access_count"] != 1 {
		t.Fatalf("portal metrics = %#v", metrics)
	}
}

func TestCustomerPortalAccessAbuseBoundaries(t *testing.T) {
	now := fixedNow()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return now }})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"sbom"}})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Customer", ExpiresAt: now.Add(4 * time.Hour)})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	access, token, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: pkg.ID, CustomerName: "ACME", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("portal access: %v", err)
	}
	if _, err := ledger.AccessCustomerPortalPackage(ctx, "evycp_wrongprefix"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-prefix token err=%v, want unauthorized", err)
	}
	metrics, err := ledger.Metrics(ctx, actor)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if metrics["customer_portal_failed_access_count"] != 0 || metrics["customer_portal_revoked_access_count"] != 0 {
		t.Fatalf("wrong-prefix attempt should not increment known-access metrics: %#v", metrics)
	}
	now = now.Add(2 * time.Hour)
	if _, err := ledger.AccessCustomerPortalPackage(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token err=%v, want unauthorized", err)
	}
	entries, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{SubjectType: "customer_portal_access", SubjectID: access.ID, Limit: 20})
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	for _, entry := range entries {
		if entry.EntryType == "customer_portal_package.access_failed" {
			t.Fatalf("expired token should not produce failed-access audit entry: %#v", entry)
		}
		if strings.Contains(entry.ActorID, token) || strings.Contains(entry.PayloadHash, token) {
			t.Fatalf("portal audit leaked token: %#v", entry)
		}
	}
}

func TestSecretHashComparisonHelper(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	hash := ledger.hashSecret("evy_test_secret")
	if !secretHashEqual(hash, hash) {
		t.Fatalf("same HMAC hash did not compare equal")
	}
	if secretHashEqual(hash, ledger.hashSecret("evy_test_other")) {
		t.Fatalf("different HMAC hashes compared equal")
	}
	if secretHashEqual(hash, "short") {
		t.Fatalf("malformed hash compared equal")
	}
}

func TestResourceGrantHelperBranchCoverage(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	admin, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, admin, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	repo, err := ledger.CreateSourceRepository(ctx, admin, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "example/api", CloneURL: "https://github.com/example/api.git", DefaultBranch: "main"})
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, admin, CreateBuildRunInput{
		ProjectID: project.ID,
		ReleaseID: release.ID,
		Provider:  "generic",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567",
		Status:    "passed",
		StartedAt: fixedNow(),
		Outputs:   []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, admin, CreateEvidenceInput{
		ProductID:   release.ProductID,
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Type:        "build",
		Title:       "Build",
		PayloadHash: sampleDigest("resource-helper"),
		SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: artifact.ID}},
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	_ = evidence
	otherProduct, err := ledger.CreateProduct(ctx, admin, "Other", "other-resource-helper")
	if err != nil {
		t.Fatalf("other product: %v", err)
	}
	otherRelease, err := ledger.CreateRelease(ctx, admin, otherProduct.ID, "1")
	if err != nil {
		t.Fatalf("other release: %v", err)
	}

	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if !ledger.productCoversRefsLocked(admin.TenantID, release.ProductID, resourceRefs{ProjectID: project.ID, SourceRepositoryID: repo.ID, ReleaseID: release.ID, BuildID: build.ID, ArtifactID: artifact.ID}) {
		t.Fatalf("product grant should cover project/source/release/build/artifact refs")
	}
	if ledger.productCoversRefsLocked(admin.TenantID, otherProduct.ID, resourceRefs{ArtifactID: artifact.ID}) {
		t.Fatalf("foreign product grant unexpectedly covered artifact")
	}
	if !ledger.projectCoversRefsLocked(admin.TenantID, project.ID, resourceRefs{ProjectID: project.ID}) {
		t.Fatalf("project grant should cover direct project ref")
	}
	if !ledger.projectCoversRefsLocked(admin.TenantID, project.ID, resourceRefs{SourceRepositoryID: repo.ID}) {
		t.Fatalf("project grant should cover source repository ref")
	}
	if !ledger.projectCoversRefsLocked(admin.TenantID, project.ID, resourceRefs{BuildID: build.ID}) {
		t.Fatalf("project grant should cover build ref")
	}
	if !ledger.releaseCoversRefsLocked(admin.TenantID, release.ID, resourceRefs{ReleaseID: release.ID}) {
		t.Fatalf("release grant should cover direct release ref")
	}
	if !ledger.releaseCoversRefsLocked(admin.TenantID, release.ID, resourceRefs{BuildID: build.ID, ArtifactID: artifact.ID}) {
		t.Fatalf("release grant should cover build and artifact refs")
	}
	if ledger.releaseCoversRefsLocked(admin.TenantID, otherRelease.ID, resourceRefs{ArtifactID: artifact.ID}) {
		t.Fatalf("foreign release grant unexpectedly covered artifact")
	}
	if !ledger.artifactCoversProductLocked(admin.TenantID, artifact.ID, release.ProductID) {
		t.Fatalf("artifact should be linked to product through evidence/build output")
	}
	if !ledger.artifactCoversReleaseLocked(admin.TenantID, artifact.ID, release.ID) {
		t.Fatalf("artifact should be linked to release through evidence/build output")
	}
	if ledger.artifactCoversReleaseLocked(admin.TenantID, artifact.ID, otherRelease.ID) {
		t.Fatalf("artifact unexpectedly covered foreign release")
	}
}

func mutateTokenSuffix(token string) string {
	if strings.HasSuffix(token, "x") {
		return token[:len(token)-1] + "y"
	}
	return token[:len(token)-1] + "x"
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

func signedTestIDToken(t *testing.T, private ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"}
	headerBody, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsBody, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBody) + "." + base64.RawURLEncoding.EncodeToString(claimsBody)
	signature := ed25519.Sign(private, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedTestRSAIDToken(t *testing.T, private *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerBody, err := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsBody, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBody) + "." + base64.RawURLEncoding.EncodeToString(claimsBody)
	signature, err := signRS256TestJWT(private, []byte(unsigned))
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func samlTestCertificate(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "saml-idp.example.test"},
		NotBefore:    fixedNow().Add(-time.Hour),
		NotAfter:     fixedNow().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return privateKey, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func signedTestSAMLAssertion(t *testing.T, privateKey *rsa.PrivateKey, issuer, audience, subject string, notBefore, notOnOrAfter time.Time) string {
	t.Helper()
	notBeforeText := notBefore.UTC().Format(time.RFC3339)
	notOnOrAfterText := notOnOrAfter.UTC().Format(time.RFC3339)
	payload := samlAssertionSignaturePayload(issuer, audience, subject, notBeforeText, notOnOrAfterText)
	sum := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign saml assertion: %v", err)
	}
	return `<Assertion ID="assertion-1" Version="2.0" IssueInstant="` + fixedNow().UTC().Format(time.RFC3339) + `">` +
		`<Issuer>` + issuer + `</Issuer>` +
		`<Subject><NameID>` + subject + `</NameID></Subject>` +
		`<Conditions NotBefore="` + notBeforeText + `" NotOnOrAfter="` + notOnOrAfterText + `">` +
		`<AudienceRestriction><Audience>` + audience + `</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`<Signature Algorithm="rsa-sha256"><SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</SignatureValue></Signature>` +
		`</Assertion>`
}

func hasVerifyCheck(checks []domain.VerifyCheck, name, result string) bool {
	for _, check := range checks {
		if check.Name == name && check.Result == result {
			return true
		}
	}
	return false
}

func bigEndianExponent(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	out := []byte{}
	for value > 0 {
		out = append([]byte{byte(value)}, out...)
		value >>= 8
	}
	return out
}

func signRS256TestJWT(private *rsa.PrivateKey, body []byte) ([]byte, error) {
	sum := sha256.Sum256(body)
	return rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, sum[:])
}
