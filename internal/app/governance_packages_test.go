package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestWaiverApprovalAndCustomerPackageFlow(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	item, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Review", PayloadHash: sampleDigest("review")})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	waiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "vendor patch pending", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	if _, err := ledger.ApproveWaiver(ctx, actor, waiver.ID); err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	approval, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "waiver", SubjectID: waiver.ID, Decision: "approved", Reason: "risk accepted", EvidenceID: item.ID})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if approval.SubjectID != waiver.ID {
		t.Fatalf("approval subject = %s, want waiver", approval.SubjectID)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"security_review"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Customer package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	accessed, err := ledger.AccessCustomerSecurityPackage(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("access package: %v", err)
	}
	if accessed.AccessCount != 1 {
		t.Fatalf("access count = %d, want 1", accessed.AccessCount)
	}
	report, err := ledger.SecurityReviewPackageReport(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("security review package report: %v", err)
	}
	if len(report.EvidenceIDs) != 1 || report.EvidenceIDs[0] != item.ID {
		t.Fatalf("report evidence ids = %#v, want package evidence", report.EvidenceIDs)
	}
	archive, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("export package archive: %v", err)
	}
	if archive.MediaType != "application/zip" || archive.Hash != hashBytes(archive.Bytes) || archive.Size != int64(len(archive.Bytes)) {
		t.Fatalf("archive metadata invalid: %#v", archive)
	}
	files := packageArchiveFiles(t, archive.Bytes)
	for _, name := range []string{"manifest.json", "package.json", "verification.json", "README.txt", "report.html"} {
		if files[name] == "" {
			t.Fatalf("archive missing %s: %#v", name, files)
		}
	}
	if report := files["report.html"]; !strings.Contains(report, "Release Summary") || !strings.Contains(report, "VEX And Vulnerability Decisions") || !strings.Contains(report, "Readiness") || !strings.Contains(report, "Verification") || !strings.Contains(report, "Limitations") || !strings.Contains(report, "not legal compliance proof") {
		t.Fatalf("HTML report missing expected sections or non-claim: %s", report)
	}
	if report := files["report.html"]; !strings.Contains(report, "http-equiv=\"Content-Security-Policy\"") || !strings.Contains(report, "default-src 'none'") || !strings.Contains(report, "form-action 'none'") {
		t.Fatalf("HTML report missing restrictive CSP meta policy: %s", report)
	}
	if strings.Contains(files["report.html"], "<script") || strings.Contains(files["report.html"], "payload_ref") || strings.Contains(files["report.html"], "internal reviewer note") {
		t.Fatalf("HTML report includes unsafe content: %s", files["report.html"])
	}
	archiveText := strings.Join([]string{files["manifest.json"], files["package.json"], files["verification.json"], files["README.txt"], files["report.html"]}, "\n")
	if !strings.Contains(archiveText, item.ID) {
		t.Fatalf("archive manifest missing package evidence id: %s", archiveText)
	}
	if strings.Contains(archiveText, `"tenant_id"`) || strings.Contains(archiveText, "legally compliant") || strings.Contains(archiveText, "certified secure") {
		t.Fatalf("archive leaked tenant internals or prohibited claims: %s", archiveText)
	}
	_, portalSecret, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: pkg.ID, CustomerName: "Customer", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("portal access: %v", err)
	}
	portalArchive, err := ledger.ExportCustomerPortalPackageArchive(ctx, portalSecret)
	if err != nil {
		t.Fatalf("portal export archive: %v", err)
	}
	if strings.Contains(strings.Join(mapValues(packageArchiveFiles(t, portalArchive.Bytes)), "\n"), portalSecret) {
		t.Fatalf("portal archive leaked access token")
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	if _, err := ledger.AccessCustomerSecurityPackage(ctx, actorB, pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant package err=%v, want not found", err)
	}
	if _, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actorB, pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant package archive err=%v, want not found", err)
	}
}

func TestCustomerPackageV2ManifestSchemaAndSensitiveFieldExclusion(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Example Org", Slug: "example-org"}); err != nil {
		t.Fatalf("organization: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	openAPIRawCanary := "RAW-OPENAPI-PAYLOAD-CANARY-EVY-201"
	baseContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "v1", []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"Payments API","version":"1","description":"`+openAPIRawCanary+`"},
		"paths":{"/v1/payments":{"get":{"operationId":"listPayments","responses":{"200":{"description":"ok"}}}}}
	}`))
	if err != nil {
		t.Fatalf("base OpenAPI contract: %v", err)
	}
	targetContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "v2", []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"Payments API","version":"2"},
		"paths":{}
	}`))
	if err != nil {
		t.Fatalf("target OpenAPI contract: %v", err)
	}
	contractDiff, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{BaseContractID: baseContract.ID, TargetContractID: targetContract.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("contract diff: %v", err)
	}
	_, _, foreignSecret, err := ledger.BootstrapTenant(ctx, "Foreign Tenant", "foreign", []string{"*"})
	if err != nil {
		t.Fatalf("foreign bootstrap: %v", err)
	}
	foreignActor, err := ledger.Authenticate(ctx, foreignSecret)
	if err != nil {
		t.Fatalf("foreign auth: %v", err)
	}
	foreignProduct, err := ledger.CreateProduct(ctx, foreignActor, "Foreign API", "foreign-api")
	if err != nil {
		t.Fatalf("foreign product: %v", err)
	}
	foreignRelease, err := ledger.CreateRelease(ctx, foreignActor, foreignProduct.ID, "9.9.9")
	if err != nil {
		t.Fatalf("foreign release: %v", err)
	}
	foreignContract, err := ledger.UploadOpenAPIContract(ctx, foreignActor, foreignProduct.ID, foreignRelease.ID, "foreign", []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"Foreign API","version":"1"},
		"paths":{"/foreign-only":{"get":{"responses":{"200":{"description":"ok"}}}}}
	}`))
	if err != nil {
		t.Fatalf("foreign OpenAPI contract: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","version":"3.1.0","purl":"pkg:apk/openssl@3.1.0"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, "CVE-2026-0700", "pkg:apk/openssl@3.1.0")
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-0700", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "manual customer-safe fallback",
		ImpactStatement: "This release is not affected based on linked release evidence.",
		ActionStatement: "No customer action is required for this finding.",
		CustomerVisible: true,
		InternalNotes:   "private manual triage note",
		VEXDocumentID:   vex.ID,
	})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	exception, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, FindingID: scan.Findings[0].ID, Reason: "temporary review exception", Owner: "security", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	if _, err := ledger.ApproveException(ctx, actor, exception.ID); err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	waiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "customer-visible package waiver", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	if _, err := ledger.ApproveWaiver(ctx, actor, waiver.ID); err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	if _, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "release reviewed for package"}); err != nil {
		t.Fatalf("approval: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest)); err != nil {
		t.Fatalf("attestation: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	bundleVerification, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID)
	if err != nil {
		t.Fatalf("verify release bundle: %v", err)
	}
	if bundleVerification.Result != string(domain.VerificationStatePassed) {
		t.Fatalf("release bundle verification = %#v", bundleVerification)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{
		Name: "customer v2",
		AllowedTypes: []string{
			"artifact", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "approval", "exception", "waiver", "build", "build_attestation", "openapi_contract", "release_bundle",
		},
	})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Customer v2 package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	manifest := pkg.Manifest
	if manifest["schema_version"] != domain.CustomerPackageSchemaVersion || manifest["package_version"] != domain.CustomerPackageSchemaVersion || manifest["package_id"] != pkg.ID {
		t.Fatalf("manifest version/id fields = %#v", manifest)
	}
	for _, key := range []string{"tenant", "organization", "product", "release", "artifact_digests", "sboms", "vulnerability_scans", "vex_documents", "vulnerability_decisions", "approvals", "exceptions", "waivers", "provenance", "api_contracts", "readiness_summary", "verification_material", "redaction_profile", "limitations", "non_claims"} {
		if _, ok := manifest[key]; !ok {
			t.Fatalf("manifest missing %s: %#v", key, manifest)
		}
	}
	verificationMaterial, ok := manifest["verification_material"].(map[string]any)
	if !ok {
		t.Fatalf("verification material has unexpected shape: %#v", manifest["verification_material"])
	}
	verificationResults, ok := verificationMaterial["verification_results"].([]map[string]any)
	if !ok || len(verificationResults) != 1 {
		t.Fatalf("verification result summaries = %#v, want one release-scoped result", verificationMaterial["verification_results"])
	}
	profileRecord, ok := verificationResults[0]["profile"].(domain.VerificationProfile)
	if !ok || profileRecord.ID != "release-bundle-signature.v1" || len(profileRecord.Limitations) == 0 {
		t.Fatalf("customer package verification profile = %#v", verificationResults[0]["profile"])
	}
	if limitations, ok := verificationResults[0]["limitations"].([]string); !ok || len(limitations) == 0 {
		t.Fatalf("customer package verification limitations = %#v", verificationResults[0]["limitations"])
	}
	apiContracts, ok := manifest["api_contracts"].(map[string]any)
	if !ok {
		t.Fatalf("api_contracts section has unexpected shape: %#v", manifest["api_contracts"])
	}
	contracts, ok := apiContracts["openapi_contracts"].([]map[string]any)
	if !ok || len(contracts) != 2 {
		t.Fatalf("openapi contract summaries = %#v, want two scoped contracts", apiContracts["openapi_contracts"])
	}
	diffs, ok := apiContracts["contract_diffs"].([]map[string]any)
	if !ok || len(diffs) != 1 || diffs[0]["id"] != contractDiff.ID || diffs[0]["result"] != "breaking" {
		t.Fatalf("contract diff summaries = %#v, want scoped breaking diff", apiContracts["contract_diffs"])
	}
	textBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	text := string(textBytes)
	for _, want := range []string{artifact.Digest, "cyclonedx", "grype", vex.ID, decision.ImpactStatement, bundle.ManifestHash, "audit_chain", baseContract.Hash, targetContract.Hash, "GET /v1/payments", "target contract has fewer paths than base contract"} {
		if !strings.Contains(text, want) {
			t.Fatalf("manifest missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"private manual triage note", openAPIRawCanary, foreignContract.ID, "foreign-only", "payload_ref", "object://", "api_key_secret", "evy_", "private_key", "session_hash"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("manifest leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, "not legal compliance proof") || strings.Contains(text, "certified secure") {
		t.Fatalf("manifest non-claims missing or unsafe: %s", text)
	}
	if _, err := customerPackageArchive(pkg); err != nil {
		t.Fatalf("package viewer/archive should load v2 manifest JSON: %v", err)
	}
}

func TestRedactionProfilePresetsAreExplicitAndSafe(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Provider:    "github_actions",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Repository:  "github.internal.example/payments/api",
		WorkflowRef: "github.internal.example/payments/api/.github/workflows/build.yml@refs/heads/main",
		RunID:       "123",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	}); err != nil {
		t.Fatalf("build: %v", err)
	}
	customerSafe, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatalf("customer-safe preset: %v", err)
	}
	if customerSafe.Name != "customer_safe" || !stringSliceContains(customerSafe.ExcludedFields, "internal_url") || stringSliceContains(customerSafe.AllowedTypes, "build") {
		t.Fatalf("customer-safe profile = %#v", customerSafe)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: customerSafe.ID, Title: "Customer safe package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("customer-safe package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal customer-safe manifest: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, `"name":"customer_safe"`) {
		t.Fatalf("manifest does not name preset profile: %s", text)
	}
	if strings.Contains(text, "github.internal.example") || strings.Contains(text, `"provenance"`) {
		t.Fatalf("customer-safe package leaked internal provenance: %s", text)
	}

	securityReview, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Preset: "security_review"})
	if err != nil {
		t.Fatalf("security-review preset: %v", err)
	}
	if !stringSliceContains(securityReview.AllowedTypes, "build") || !stringSliceContains(securityReview.AllowedTypes, "build_attestation") {
		t.Fatalf("security-review profile missing provenance types: %#v", securityReview)
	}
	securityPkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: securityReview.ID, Title: "Security review package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("security-review package: %v", err)
	}
	securityBody, err := json.Marshal(securityPkg.Manifest)
	if err != nil {
		t.Fatalf("marshal security-review manifest: %v", err)
	}
	if !strings.Contains(string(securityBody), `"provenance"`) {
		t.Fatalf("security-review package missing provenance: %s", securityBody)
	}

	if _, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Preset: "customer_safe", AllowedTypes: []string{"build"}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("preset override err=%v, want validation", err)
	}
	if _, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "unsafe"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unsafe unscoped profile err=%v, want validation", err)
	}
}

func TestCustomerPackageGapsRespectRedactionProfile(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	customerSafe, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatalf("customer-safe profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: customerSafe.ID, Title: "Gap package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("customer-safe package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, `"customer_safe_gaps"`) || !strings.Contains(text, `"evidence_type":"sbom"`) || !strings.Contains(text, `"customer_visible":true`) {
		t.Fatalf("customer-safe gaps missing: %s", text)
	}
	internalOnly, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "decision-only", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("decision-only profile: %v", err)
	}
	internalPkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: internalOnly.ID, Title: "Decision-only package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("decision-only package: %v", err)
	}
	body, err = json.Marshal(internalPkg.Manifest)
	if err != nil {
		t.Fatalf("marshal decision-only package: %v", err)
	}
	if strings.Contains(string(body), `"customer_safe_gaps"`) || strings.Contains(string(body), `"evidence_type":"sbom"`) {
		t.Fatalf("internal-only profile leaked excluded gaps: %s", body)
	}
}

func packageArchiveFiles(t *testing.T, body []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	files := map[string]string{}
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		files[file.Name] = string(content)
	}
	return files
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func TestTemplatesReportsEvidenceBundleAndCRAHTML(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "sbom", Title: "SBOM", PayloadHash: sampleDigest("sbom")}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	packs, err := ledger.ListControlFrameworkTemplatePacks(ctx, actor)
	if err != nil {
		t.Fatalf("template packs: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("expected built-in packs")
	}
	framework, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, "evydence-cra-readiness")
	if err != nil {
		t.Fatalf("install pack: %v", err)
	}
	if framework.Slug != "evydence-cra-readiness" {
		t.Fatalf("framework slug = %s", framework.Slug)
	}
	htmlPkg, err := ledger.CRAReadinessHTMLPackage(ctx, actor, release.ProductID, release.ID)
	if err != nil {
		t.Fatalf("CRA HTML: %v", err)
	}
	if htmlPkg.Hash == "" || htmlPkg.HTML == "" {
		t.Fatalf("html package = %#v", htmlPkg)
	}
	tpl, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "simple", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_type", "subject_id"}, Template: "json"})
	if err != nil {
		t.Fatalf("report template: %v", err)
	}
	rendered, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: tpl.ID, SubjectType: "release", SubjectID: release.ID})
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	if rendered.Output["subject_id"] != release.ID || rendered.Hash == "" {
		t.Fatalf("rendered report = %#v", rendered)
	}
	bundle, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, nil)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	if bundle.ManifestHash == "" || len(bundle.EvidenceIDs) == 0 {
		t.Fatalf("bundle = %#v", bundle)
	}
	imported, err := ledger.ImportEvidenceBundle(ctx, actor, bundle)
	if err != nil {
		t.Fatalf("import bundle: %v", err)
	}
	if imported.ImportedCount != len(bundle.EvidenceIDs) {
		t.Fatalf("imported count = %d want %d", imported.ImportedCount, len(bundle.EvidenceIDs))
	}
}

func TestDSSETrustRootVerification(t *testing.T) {
	objectStore := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, ObjectStore: objectStore})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	statement := map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": []map[string]any{{"name": "api.tar.gz", "digest": map[string]string{"sha256": artifact.Digest[len("sha256:"):]}}}, "predicate": map[string]any{"builder": map[string]string{"id": "builder"}, "buildType": "test", "materials": []any{}}}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	envelope, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	att, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, envelope)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if _, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatalf("trust root: %v", err)
	}
	vr, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, att.ID)
	if err != nil {
		t.Fatalf("verify dsse: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("verification result = %s", vr.Result)
	}
}

type testObjectStore struct {
	objects map[string]Object
}

func newTestObjectStore() *testObjectStore {
	return &testObjectStore{objects: map[string]Object{}}
}

func (s *testObjectStore) Put(_ context.Context, object Object) error {
	s.objects[object.Key] = object
	return nil
}

func (s *testObjectStore) Get(_ context.Context, key string) (Object, error) {
	object, ok := s.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	return object, nil
}
