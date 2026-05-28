package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	fsobject "github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreLoadSaveAndOutboxWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	state := app.PersistedState{
		Tenants: map[string]domain.Tenant{
			"ten_test": {ID: "ten_test", Name: "Test", CreatedAt: time.Now().UTC()},
		},
		Organizations: map[string]domain.Organization{
			"org_test": {ID: "org_test", TenantID: "ten_test", Name: "Org", Slug: "org", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Users: map[string]domain.HumanUser{
			"user_test": {ID: "user_test", TenantID: "ten_test", OrganizationID: "org_test", Email: "user@example.test", DisplayName: "User", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RoleBindings: map[string]domain.RoleBinding{
			"rb_test": {ID: "rb_test", TenantID: "ten_test", SubjectType: "user", SubjectID: "user_test", Role: "security_engineer", SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		APIKeys: map[string]domain.APIKey{
			"key_test": {ID: "key_test", TenantID: "ten_test", Name: "api", Prefix: "evy_test", Scopes: []string{"evidence:write"}, CreatedAt: time.Now().UTC()},
		},
		APIKeyHashes: map[string]string{"key_test": "hmac-test-hash"},
		SSOProviders: map[string]domain.SSOProvider{
			"sso_test": {ID: "sso_test", TenantID: "ten_test", Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", Status: "active", JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "kid-1", "crv": "Ed25519", "x": "abc"}}}, SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: time.Now().UTC(), TrustMaterialUpdatedAt: ptrTime(time.Now().UTC())},
		},
		IdentityLinks: map[string]domain.UserIdentityLink{
			"link_test": {ID: "link_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Subject: "sub", Email: "user@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		SSOSessions: map[string]domain.SSOSession{
			"sess_test": {ID: "sess_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Prefix: "sess", ExpiresAt: time.Now().UTC().Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SSOSessionHashes: map[string]string{"sess_test": "session-hash"},
		CustomerPortalAccess: map[string]domain.CustomerPortalAccess{
			"cpa_test": {ID: "cpa_test", TenantID: "ten_test", PackageID: "pkg_test", CustomerName: "Customer", Prefix: "evycp_test", ExpiresAt: time.Now().UTC().Add(time.Hour), AccessCount: 2, FailedAccessCount: 1, LastAccessedAt: ptrTime(time.Now().UTC()), LastFailedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: time.Now().UTC()},
		},
		CustomerPortalHashes: map[string]string{"cpa_test": "portal-token-hash"},
		Products: map[string]domain.Product{
			"prod_test": {ID: "prod_test", TenantID: "ten_test", Name: "Product", Slug: "product", CreatedAt: time.Now().UTC()},
		},
		Projects: map[string]domain.Project{
			"proj_test": {ID: "proj_test", TenantID: "ten_test", ProductID: "prod_test", Name: "API", CreatedAt: time.Now().UTC()},
		},
		Releases: map[string]domain.Release{
			"rel_test": {ID: "rel_test", TenantID: "ten_test", ProductID: "prod_test", Version: "1.0.0", State: "open", CreatedAt: time.Now().UTC()},
		},
		Artifacts: map[string]domain.Artifact{
			"art_test": {ID: "art_test", TenantID: "ten_test", Name: "artifact.tar.gz", MediaType: "application/gzip", Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: time.Now().UTC()},
		},
		Evidence: map[string]domain.EvidenceItem{
			"ev_test": {
				ID: "ev_test", TenantID: "ten_test", ProductID: "prod_test", ProjectID: "proj_test", ReleaseID: "rel_test",
				Type: "sbom", Subtype: "cyclonedx", Title: "SBOM", SourceSystem: "test", ObservedAt: time.Now().UTC(),
				EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadRef: "object://tenants/ten_test/payloads/sbom/" + strings.Repeat("b", 64),
				PayloadHash: "sha256:" + strings.Repeat("b", 64), PayloadMediaType: "application/json", PayloadSize: 123,
				CanonicalHash: "sha256:" + strings.Repeat("c", 64), Canonicalization: domain.CanonicalizationProfileVersion,
				SubjectRefs: []domain.SubjectRef{{Type: "release", ID: "rel_test"}}, TrustLevel: "uploaded", VerificationStatus: "verified",
				Tags: []string{"release"}, Metadata: map[string]any{"parser": "test"}, CreatedAt: time.Now().UTC(),
			},
		},
		Chain: map[string][]domain.AuditChainEntry{
			"ten_test": {{
				ID: "chain_test", TenantID: "ten_test", Sequence: 1, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: "ev_test",
				ActorType: "user", ActorID: "user_test", OccurredAt: time.Now().UTC(), PayloadHash: "sha256:" + strings.Repeat("b", 64),
				CanonicalEntryHash: "sha256:" + strings.Repeat("d", 64), PreviousEntryHash: "", EntryHash: "sha256:" + strings.Repeat("e", 64),
				SchemaVersion: domain.AuditChainEntrySchemaVersion,
			}},
		},
		SigningKeys: map[string]domain.SigningKey{
			"sigkey_test": {ID: "sigkey_test", TenantID: "ten_test", KID: "kid-test", Algorithm: "Ed25519", Status: "active", PublicKey: "public", CreatedAt: time.Now().UTC()},
		},
		SigningKeyPrivate: map[string][]byte{"sigkey_test": []byte("dev-private-key")},
		Signatures: map[string]domain.Signature{
			"sig_test": {ID: "sig_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "bundle_test", KeyID: "sigkey_test", Algorithm: "Ed25519", Value: "signature", CreatedAt: time.Now().UTC()},
		},
		SBOMs: map[string]domain.SBOM{
			"sbom_test": {ID: "sbom_test", TenantID: "ten_test", EvidenceID: "ev_test", ReleaseID: "rel_test", ArtifactID: "art_test", Format: "cyclonedx", SpecVersion: "1.5", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "lib", Version: "1.0.0"}}, CreatedAt: time.Now().UTC()},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {ID: "scan_test", TenantID: "ten_test", EvidenceID: "ev_test", ReleaseID: "rel_test", Scanner: "scanner", TargetRef: "artifact.tar.gz", Summary: map[string]int{"critical": 0}, Findings: []domain.VulnerabilityFinding{{ID: "finding_test", Vulnerability: "CVE-0000-0001", Severity: "low", State: "open"}}, CreatedAt: time.Now().UTC()},
		},
		Contracts: map[string]domain.OpenAPIContract{
			"contract_test": {ID: "contract_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", Version: "1.0.0", Hash: "sha256:" + strings.Repeat("f", 64), PathCount: 1, Operations: []domain.OpenAPIOperation{{Path: "/v1/test", Method: "get", OperationID: "getTest"}}, EvidenceID: "ev_test", CreatedAt: time.Now().UTC()},
		},
		Policies: map[string]domain.PolicyEvaluation{
			"policy_test": {ID: "policy_test", TenantID: "ten_test", ReleaseID: "rel_test", Result: "pass", PolicySet: domain.PolicySetVersion, Checks: []domain.PolicyCheck{{Name: "sbom", Result: "passed", Severity: "high", Explanation: "test"}}, CreatedAt: time.Now().UTC()},
		},
		Bundles: map[string]domain.ReleaseBundle{
			"bundle_test": {ID: "bundle_test", TenantID: "ten_test", ReleaseID: "rel_test", State: "generated", Manifest: map[string]any{"release_id": "rel_test"}, ManifestHash: "sha256:" + strings.Repeat("1", 64), SignatureRefs: []string{"sig_test"}, CreatedAt: time.Now().UTC()},
		},
		Verifications: map[string]domain.VerificationResult{
			"verify_test": {ID: "verify_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "bundle_test", Result: "pass", Checks: []domain.VerifyCheck{{Name: "signature", Result: "passed"}}, VerifiedAt: time.Now().UTC()},
		},
		RedactionProfiles: map[string]domain.RedactionProfile{
			"redact_test": {ID: "redact_test", TenantID: "ten_test", Name: "Default", Description: "profile", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"metadata.secret"}, SchemaVersion: domain.RedactionProfileSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CustomerPackages: map[string]domain.CustomerSecurityPackage{
			"pkg_test": {ID: "pkg_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", RedactionProfileID: "redact_test", Title: "Package", State: "generated", Manifest: map[string]any{"release_id": "rel_test"}, ManifestHash: "sha256:" + strings.Repeat("2", 64), ExpiresAt: time.Now().UTC().Add(24 * time.Hour), AccessCount: 3, SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		HTMLReports: map[string]domain.HTMLReportPackage{
			"html_test": {ID: "html_test", TenantID: "ten_test", ReportType: "cra_readiness", ProductID: "prod_test", ReleaseID: "rel_test", HTML: "<html></html>", Hash: "sha256:" + strings.Repeat("3", 64), SchemaVersion: "html-report-package.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		ReportTemplates: map[string]domain.CustomReportTemplate{
			"tpl_test": {ID: "tpl_test", TenantID: "ten_test", Name: "report", Version: "1", ReportType: "custom", AllowedFields: []string{"id"}, Template: "{{id}}", SchemaVersion: domain.ReportTemplateSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RenderedReports: map[string]domain.RenderedCustomReport{
			"render_test": {ID: "render_test", TenantID: "ten_test", TemplateID: "tpl_test", SubjectType: "release", SubjectID: "rel_test", Output: map[string]any{"id": "rel_test"}, Hash: "sha256:" + strings.Repeat("4", 64), SchemaVersion: "rendered-report.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		EvidenceBundles: map[string]domain.EvidenceBundle{
			"eb_test": {ID: "eb_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceIDs: []string{"ev_test"}, Manifest: map[string]any{"evidence_ids": []any{"ev_test"}}, ManifestHash: "sha256:" + strings.Repeat("5", 64), SignatureRefs: []string{"sig_test"}, VerificationText: "verify", SchemaVersion: domain.EvidenceBundleSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		BundleImports: map[string]domain.EvidenceBundleImport{
			"ebi_test": {ID: "ebi_test", TenantID: "ten_test", BundleHash: "sha256:" + strings.Repeat("5", 64), Result: "imported", ImportedCount: 1, SchemaVersion: domain.EvidenceBundleImportVersion, CreatedAt: time.Now().UTC()},
		},
		ObjectRetentionPolicies: map[string]domain.ObjectRetentionPolicy{
			"orp_test": {ID: "orp_test", TenantID: "ten_test", Name: "retain", ObjectPrefix: "tenants/ten_test/", Mode: "governance", RetentionDays: 30, Status: "verified", VerifiedAt: ptrTime(time.Now().UTC()), VerificationHash: "sha256:" + strings.Repeat("6", 64), VerificationChecks: []domain.VerifyCheck{{Name: "versioning", Result: "passed"}}, VerificationLimitations: []string{"test"}, SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: time.Now().UTC()},
		},
		BackupManifests: map[string]domain.BackupManifest{
			"bak_test": {ID: "bak_test", TenantID: "ten_test", StateHash: "sha256:" + strings.Repeat("7", 64), ResourceCounts: map[string]int{"evidence": 1}, ConsistencyChecks: []domain.VerifyCheck{{Name: "chain", Result: "passed"}}, Limitations: []string{"objects separately backed up"}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		LegalHolds: map[string]domain.LegalHold{
			"hold_test": {ID: "hold_test", TenantID: "ten_test", ScopeType: "release", ScopeID: "rel_test", Reason: "review", Owner: "security", ReleasedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RetentionOverrides: map[string]domain.RetentionOverride{
			"ret_test": {ID: "ret_test", TenantID: "ten_test", ScopeType: "release", ScopeID: "rel_test", RetentionUntil: time.Now().UTC().Add(365 * 24 * time.Hour), Reason: "policy", Owner: "security", SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		QuestionnaireTemplates: map[string]domain.QuestionnaireTemplate{
			"qt_test": {ID: "qt_test", TenantID: "ten_test", Name: "questionnaire", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Evidence?", EvidenceType: "sbom"}}, SchemaVersion: domain.QuestionnaireTemplateVersion, CreatedAt: time.Now().UTC()},
		},
		QuestionnairePackages: map[string]domain.QuestionnairePackage{
			"qp_test": {ID: "qp_test", TenantID: "ten_test", TemplateID: "qt_test", PackageID: "pkg_test", ProductID: "prod_test", ReleaseID: "rel_test", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "See evidence", EvidenceIDs: []string{"ev_test"}}}, ManifestHash: "sha256:" + strings.Repeat("8", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: time.Now().UTC()},
		},
		PDFReports: map[string]domain.PDFReportPackage{
			"pdf_test": {ID: "pdf_test", TenantID: "ten_test", ReportType: "cra_readiness", ProductID: "prod_test", ReleaseID: "rel_test", Title: "PDF", PayloadRef: "object://tenants/ten_test/reports/pdf", PayloadHash: "sha256:" + strings.Repeat("9", 64), PayloadSize: 10, Limitations: []string{"test"}, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: time.Now().UTC()},
		},
		AnomalyReports: map[string]domain.AnomalyReport{
			"anom_test": {ID: "anom_test", TenantID: "ten_test", SubjectType: "release", SubjectID: "rel_test", Result: "review", Signals: []domain.AnomalySignal{{Name: "gap", Severity: "medium", Detail: "test"}}, Assumptions: []string{"heuristic"}, Limitations: []string{"not ML"}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: time.Now().UTC()},
		},
		Idempotency: map[string]app.IdempotencyRecord{
			app.NewIdempotencyRecordKey("ten_test", "user:user_test", "POST", "/v1/products", "idem"): {RequestHash: "sha256:request", Status: 201, Response: map[string]any{"ok": true}, CreatedAt: time.Now().UTC()},
		},
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Tenants["ten_test"].ID != "ten_test" {
		t.Fatalf("unexpected loaded state: ok=%v state=%#v", ok, got.Tenants)
	}
	var indexed int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_index WHERE tenant_id = 'ten_test' AND resource_type = 'tenant'`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 1 {
		t.Fatalf("resource index rows = %d, want 1", indexed)
	}
	var apiKeyHash string
	if err := store.pool.QueryRow(ctx, `SELECT hash FROM api_keys WHERE id = 'key_test' AND tenant_id = 'ten_test'`).Scan(&apiKeyHash); err != nil {
		t.Fatal(err)
	}
	if apiKeyHash != "hmac-test-hash" {
		t.Fatalf("api key hash = %q", apiKeyHash)
	}
	var userRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM human_users WHERE tenant_id = 'ten_test' AND email = 'user@example.test'`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if userRows != 1 {
		t.Fatalf("human user rows = %d, want 1", userRows)
	}
	var ssoTrustRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM sso_providers WHERE id = 'sso_test' AND trust_material_updated_at IS NOT NULL AND jwks <> '{}'::jsonb`).Scan(&ssoTrustRows); err != nil {
		t.Fatal(err)
	}
	if ssoTrustRows != 1 {
		t.Fatalf("sso trust rows = %d, want 1", ssoTrustRows)
	}
	var idemActor string
	if err := store.pool.QueryRow(ctx, `SELECT actor_key_id FROM idempotency_records WHERE tenant_id = 'ten_test' AND idempotency_key = 'idem'`).Scan(&idemActor); err != nil {
		t.Fatal(err)
	}
	if idemActor != "user:user_test" {
		t.Fatalf("idempotency actor = %q", idemActor)
	}
	var portalHash string
	if err := store.pool.QueryRow(ctx, `SELECT hash FROM customer_portal_access WHERE id = 'cpa_test' AND failed_access_count = 1 AND last_accessed_at IS NOT NULL`).Scan(&portalHash); err != nil {
		t.Fatal(err)
	}
	if portalHash != "portal-token-hash" {
		t.Fatalf("portal hash = %q", portalHash)
	}
	coreChecks := []struct {
		name  string
		query string
	}{
		{name: "product", query: `SELECT count(*) FROM products WHERE tenant_id = 'ten_test' AND id = 'prod_test'`},
		{name: "project", query: `SELECT count(*) FROM projects WHERE tenant_id = 'ten_test' AND product_id = 'prod_test'`},
		{name: "release", query: `SELECT count(*) FROM releases WHERE tenant_id = 'ten_test' AND id = 'rel_test'`},
		{name: "artifact", query: `SELECT count(*) FROM artifacts WHERE tenant_id = 'ten_test' AND digest LIKE 'sha256:%'`},
		{name: "evidence", query: `SELECT count(*) FROM evidence_items WHERE tenant_id = 'ten_test' AND id = 'ev_test' AND evidence_version = 1 AND product_id = 'prod_test'`},
		{name: "audit chain", query: `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = 'ten_test' AND sequence = 1`},
		{name: "signing key", query: `SELECT count(*) FROM signing_keys WHERE tenant_id = 'ten_test' AND id = 'sigkey_test' AND encrypted_private_key IS NOT NULL`},
		{name: "signature", query: `SELECT count(*) FROM signatures WHERE tenant_id = 'ten_test' AND id = 'sig_test'`},
		{name: "sbom", query: `SELECT count(*) FROM sboms WHERE tenant_id = 'ten_test' AND release_id = 'rel_test' AND component_count = 1`},
		{name: "scan", query: `SELECT count(*) FROM vulnerability_scans WHERE tenant_id = 'ten_test' AND release_id = 'rel_test'`},
		{name: "contract", query: `SELECT count(*) FROM openapi_contracts WHERE tenant_id = 'ten_test' AND id = 'contract_test' AND operations <> '[]'::jsonb`},
		{name: "policy", query: `SELECT count(*) FROM policy_evaluations WHERE tenant_id = 'ten_test' AND id = 'policy_test'`},
		{name: "bundle", query: `SELECT count(*) FROM release_bundles WHERE tenant_id = 'ten_test' AND id = 'bundle_test'`},
		{name: "verification", query: `SELECT count(*) FROM verification_results WHERE tenant_id = 'ten_test' AND id = 'verify_test'`},
		{name: "redaction profile", query: `SELECT count(*) FROM redaction_profiles WHERE tenant_id = 'ten_test' AND id = 'redact_test' AND allowed_types = ARRAY['sbom']`},
		{name: "customer package", query: `SELECT count(*) FROM customer_security_packages WHERE tenant_id = 'ten_test' AND id = 'pkg_test' AND access_count = 3`},
		{name: "html report", query: `SELECT count(*) FROM html_report_packages WHERE tenant_id = 'ten_test' AND id = 'html_test'`},
		{name: "report template", query: `SELECT count(*) FROM report_templates WHERE tenant_id = 'ten_test' AND id = 'tpl_test'`},
		{name: "rendered report", query: `SELECT count(*) FROM rendered_reports WHERE tenant_id = 'ten_test' AND id = 'render_test'`},
		{name: "evidence bundle", query: `SELECT count(*) FROM evidence_bundles WHERE tenant_id = 'ten_test' AND id = 'eb_test'`},
		{name: "evidence bundle import", query: `SELECT count(*) FROM evidence_bundle_imports WHERE tenant_id = 'ten_test' AND id = 'ebi_test'`},
		{name: "object retention", query: `SELECT count(*) FROM object_retention_policies WHERE tenant_id = 'ten_test' AND id = 'orp_test' AND verification_checks <> '[]'::jsonb`},
		{name: "backup manifest", query: `SELECT count(*) FROM backup_manifests WHERE tenant_id = 'ten_test' AND id = 'bak_test'`},
		{name: "legal hold", query: `SELECT count(*) FROM legal_holds WHERE tenant_id = 'ten_test' AND id = 'hold_test' AND released_at IS NOT NULL`},
		{name: "retention override", query: `SELECT count(*) FROM retention_overrides WHERE tenant_id = 'ten_test' AND id = 'ret_test'`},
		{name: "questionnaire template", query: `SELECT count(*) FROM questionnaire_templates WHERE tenant_id = 'ten_test' AND id = 'qt_test'`},
		{name: "questionnaire package", query: `SELECT count(*) FROM questionnaire_packages WHERE tenant_id = 'ten_test' AND id = 'qp_test'`},
		{name: "pdf report", query: `SELECT count(*) FROM pdf_report_packages WHERE tenant_id = 'ten_test' AND id = 'pdf_test'`},
		{name: "anomaly report", query: `SELECT count(*) FROM anomaly_reports WHERE tenant_id = 'ten_test' AND id = 'anom_test'`},
	}
	for _, check := range coreChecks {
		var rows int
		if err := store.pool.QueryRow(ctx, check.query).Scan(&rows); err != nil {
			t.Fatalf("%s relational row query: %v", check.name, err)
		}
		if rows != 1 {
			t.Fatalf("%s relational rows = %d, want 1", check.name, rows)
		}
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM ledger_state WHERE id = 'default'`); err != nil {
		t.Fatal(err)
	}
	relational, ok, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected relational state fallback after removing snapshot")
	}
	if relational.APIKeyHashes["key_test"] != "hmac-test-hash" {
		t.Fatalf("relational api key hash = %q", relational.APIKeyHashes["key_test"])
	}
	if relational.Organizations["org_test"].Slug != "org" || relational.Users["user_test"].OrganizationID != "org_test" || relational.RoleBindings["rb_test"].Role != "security_engineer" {
		t.Fatalf("relational identity rows missing: org=%#v user=%#v role=%#v", relational.Organizations["org_test"], relational.Users["user_test"], relational.RoleBindings["rb_test"])
	}
	if relational.SSOProviders["sso_test"].TrustMaterialUpdatedAt == nil || len(relational.SSOProviders["sso_test"].JWKS) == 0 || !relational.IdentityLinks["link_test"].Verified {
		t.Fatalf("relational sso rows missing: provider=%#v link=%#v", relational.SSOProviders["sso_test"], relational.IdentityLinks["link_test"])
	}
	if relational.SSOSessionHashes["sess_test"] != "session-hash" || relational.SSOSessions["sess_test"].Prefix != "sess" {
		t.Fatalf("relational sso session = %#v hash=%q", relational.SSOSessions["sess_test"], relational.SSOSessionHashes["sess_test"])
	}
	if relational.Products["prod_test"].Slug != "product" || relational.Evidence["ev_test"].ReleaseID != "rel_test" || relational.SBOMs["sbom_test"].ComponentCount != 1 {
		t.Fatalf("relational fallback missing core rows: product=%#v evidence=%#v sbom=%#v", relational.Products["prod_test"], relational.Evidence["ev_test"], relational.SBOMs["sbom_test"])
	}
	if relational.Contracts["contract_test"].PathCount != 1 || len(relational.Contracts["contract_test"].Operations) != 1 {
		t.Fatalf("relational fallback contract = %#v", relational.Contracts["contract_test"])
	}
	if len(relational.Chain["ten_test"]) != 1 || relational.Bundles["bundle_test"].ManifestHash == "" || relational.Verifications["verify_test"].Result != "pass" {
		t.Fatalf("relational fallback integrity rows missing: chain=%#v bundle=%#v verification=%#v", relational.Chain["ten_test"], relational.Bundles["bundle_test"], relational.Verifications["verify_test"])
	}
	if len(relational.SigningKeyPrivate["sigkey_test"]) == 0 {
		t.Fatal("relational fallback missing local dev signing key bytes")
	}
	if len(relational.Idempotency) != 1 {
		t.Fatalf("relational idempotency records = %d, want 1", len(relational.Idempotency))
	}
	if relational.CustomerPortalHashes["cpa_test"] != "portal-token-hash" || relational.CustomerPortalAccess["cpa_test"].FailedAccessCount != 1 {
		t.Fatalf("relational portal access = %#v hash=%q", relational.CustomerPortalAccess["cpa_test"], relational.CustomerPortalHashes["cpa_test"])
	}
	if relational.RedactionProfiles["redact_test"].Name != "Default" || relational.CustomerPackages["pkg_test"].AccessCount != 3 {
		t.Fatalf("relational package rows missing: redaction=%#v package=%#v", relational.RedactionProfiles["redact_test"], relational.CustomerPackages["pkg_test"])
	}
	if relational.HTMLReports["html_test"].Hash == "" || relational.ReportTemplates["tpl_test"].Template == "" || relational.RenderedReports["render_test"].Hash == "" {
		t.Fatalf("relational report rows missing: html=%#v template=%#v rendered=%#v", relational.HTMLReports["html_test"], relational.ReportTemplates["tpl_test"], relational.RenderedReports["render_test"])
	}
	if relational.EvidenceBundles["eb_test"].ManifestHash == "" || relational.BundleImports["ebi_test"].ImportedCount != 1 {
		t.Fatalf("relational evidence bundle rows missing: bundle=%#v import=%#v", relational.EvidenceBundles["eb_test"], relational.BundleImports["ebi_test"])
	}
	if relational.ObjectRetentionPolicies["orp_test"].Status != "verified" || len(relational.ObjectRetentionPolicies["orp_test"].VerificationChecks) != 1 {
		t.Fatalf("relational object retention policy = %#v", relational.ObjectRetentionPolicies["orp_test"])
	}
	if relational.BackupManifests["bak_test"].ResourceCounts["evidence"] != 1 || relational.LegalHolds["hold_test"].ReleasedAt == nil || relational.RetentionOverrides["ret_test"].Owner != "security" {
		t.Fatalf("relational retention rows missing: backup=%#v hold=%#v override=%#v", relational.BackupManifests["bak_test"], relational.LegalHolds["hold_test"], relational.RetentionOverrides["ret_test"])
	}
	if len(relational.QuestionnaireTemplates["qt_test"].Questions) != 1 || len(relational.QuestionnairePackages["qp_test"].Responses) != 1 {
		t.Fatalf("relational questionnaire rows missing: template=%#v package=%#v", relational.QuestionnaireTemplates["qt_test"], relational.QuestionnairePackages["qp_test"])
	}
	if relational.PDFReports["pdf_test"].PayloadHash == "" || relational.AnomalyReports["anom_test"].Result != "review" {
		t.Fatalf("relational generated report rows missing: pdf=%#v anomaly=%#v", relational.PDFReports["pdf_test"], relational.AnomalyReports["anom_test"])
	}
	job := app.OutboxJob{ID: "job_test_" + time.Now().Format("150405.000000000"), TenantID: "ten_test", Kind: "verify_subject", SubjectType: "audit_chain", SubjectID: "audit_chain", CreatedAt: time.Now().UTC()}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ClaimJobs(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("expected claimed job")
	}
	if err := store.CompleteJob(ctx, jobs[0].ID); err != nil {
		t.Fatal(err)
	}

	retryJob := app.OutboxJob{ID: "job_retry_" + time.Now().Format("150405.000000000"), TenantID: "ten_test", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom_test", CreatedAt: time.Now().UTC()}
	if err := store.Enqueue(ctx, retryJob); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.CountPendingJobs(ctx); err != nil {
		t.Fatal(err)
	} else if pending == 0 {
		t.Fatal("expected pending outbox job")
	}
	claimed, err := store.ClaimJobs(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) == 0 {
		t.Fatal("expected retry job claim")
	}
	if err := store.FailJob(ctx, claimed[0].ID, context.Canceled); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Now(ctx); err != nil {
		t.Fatal(err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func TestPendingMigrationVersionsWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	baseStore, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer baseStore.Close()
	schema := "evydence_pending_migrations_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := baseStore.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = baseStore.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.PendingMigrationVersions(ctx, "../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := migrationFileNames(t, "../../../migrations")
	if len(pending) != len(names) {
		t.Fatalf("pending migrations = %d, want %d", len(pending), len(names))
	}
	if err := store.RequireNoPendingMigrations(ctx, "../../../migrations"); err == nil {
		t.Fatal("expected pending migrations to fail closed")
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingMigrationVersions(ctx, "../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after apply = %#v", pending)
	}
	if err := store.RequireNoPendingMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("require no pending after apply: %v", err)
	}
}

func TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjects(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	baseStore, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer baseStore.Close()
	sourceSchema := "evydence_restore_source_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	targetSchema := "evydence_restore_target_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	for _, schema := range []string{sourceSchema, targetSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := baseStore.pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		defer func(schema string) {
			_, _ = baseStore.pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		}(schema)
	}

	sourceStore, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, sourceSchema))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	if _, err := sourceStore.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	sourceObjectRoot := t.TempDir()
	sourceObjects, err := fsobject.New(sourceObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := app.NewLedgerWithError(app.Config{APIKeyPepper: "test-pepper", Store: sourceStore, ObjectStore: sourceObjects})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Restore Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-restore")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments.tar.gz", "application/gzip", "sha256:"+strings.Repeat("a", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	dbBackup, ok, err := sourceStore.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load backup state ok=%v err=%v", ok, err)
	}

	targetStore, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, targetSchema))
	if err != nil {
		t.Fatal(err)
	}
	defer targetStore.Close()
	if _, err := targetStore.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	if err := targetStore.SaveState(ctx, dbBackup); err != nil {
		t.Fatal(err)
	}
	targetObjectRoot := t.TempDir()
	copyTree(t, sourceObjectRoot, targetObjectRoot)
	targetObjects, err := fsobject.New(targetObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := app.NewLedgerWithError(app.Config{APIKeyPepper: "test-pepper", Store: targetStore, ObjectStore: targetObjects})
	if err != nil {
		t.Fatal(err)
	}
	restoredActor, err := restored.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.VerifyBackupManifest(ctx, restoredActor, manifest.ID); err != nil {
		t.Fatalf("verify backup manifest after restore: %v", err)
	}
	restoredSBOM, err := restored.GetSBOM(ctx, restoredActor, sbom.ID)
	if err != nil || restoredSBOM.ComponentCount != sbom.ComponentCount {
		t.Fatalf("restored sbom = %#v err=%v", restoredSBOM, err)
	}
	evidence, err := restored.GetEvidence(ctx, restoredActor, restoredSBOM.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := strings.TrimPrefix(evidence.PayloadRef, "object://")
	object, err := targetObjects.Get(ctx, objectKey)
	if err != nil {
		t.Fatalf("restored object: %v", err)
	}
	if object.Digest != evidence.PayloadHash {
		t.Fatalf("restored object digest = %q, want %q", object.Digest, evidence.PayloadHash)
	}
	if vr, err := restored.VerifySubject(ctx, restoredActor, "release_bundle", bundle.ID); err != nil || vr.Result != "passed" {
		t.Fatalf("verify restored bundle = %#v err=%v", vr, err)
	}
}

func copyTree(t *testing.T, sourceRoot, targetRoot string) {
	t.Helper()
	if err := os.CopyFS(targetRoot, os.DirFS(sourceRoot)); err != nil {
		t.Fatal(err)
	}
}
