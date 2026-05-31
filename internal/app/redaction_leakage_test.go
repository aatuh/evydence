package app

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCustomerPackageRedactionLeakageMatrix(t *testing.T) {
	objects := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, ObjectStore: objects})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)

	_, apiSecret, err := ledger.CreateAPIKey(ctx, actor, "leakage-test-key", []string{ScopeEvidenceRead}, nil)
	if err != nil {
		t.Fatalf("api key: %v", err)
	}
	internalNote := "INTERNAL-TRIAGE-NOTE-EVY-101"
	internalURL := "https://internal.example.test/runbooks/evy-101"
	rawScannerPayload := "RAW-SCANNER-PAYLOAD-EVY-101"
	tenantSecret := "TENANT-SECRET-EVY-101"
	privateMaterialCanary := "PRIVATE-SIGNING-MATERIAL-EVY-101"

	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","version":"3.1.0","purl":"pkg:apk/openssl@3.1.0"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-1100","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("vulnerability scan: %v", err)
	}
	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "internal review references " + internalURL,
		ImpactStatement: "This release is not affected based on the customer-visible release evidence.",
		ActionStatement: "Internal runbook: " + internalURL,
		CustomerVisible: true,
		InternalNotes:   internalNote,
	})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   release.ProductID,
		ReleaseID:   release.ID,
		Type:        "security_review",
		Title:       "Internal review",
		PayloadRef:  "object://tenants/" + actor.TenantID + "/payloads/manual/" + privateMaterialCanary,
		PayloadHash: sampleDigest("review"),
		Metadata: map[string]any{
			"tenant_secret": tenantSecret,
			"internal_url":  internalURL,
			"private_key":   privateMaterialCanary,
		},
		SourceIdentity: map[string]any{"internal_url": internalURL},
	}); err != nil {
		t.Fatalf("internal evidence: %v", err)
	}
	securityScan, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{
		ProductID:  release.ProductID,
		ReleaseID:  release.ID,
		ArtifactID: artifact.ID,
		Category:   "secret_scan",
		Format:     "generic",
		Scanner:    "internal-secret-scanner",
		TargetRef:  "pkg:oci/payments-api",
		Raw:        []byte(`{"findings":[{"severity":"` + rawScannerPayload + `"}]}`),
	})
	if err != nil {
		t.Fatalf("security scan: %v", err)
	}
	addBuildProvenance(t, ledger, actor, release, artifact)
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	var privateKeyMaterial string
	ledger.mu.Lock()
	for _, key := range ledger.signingKeys {
		if key.TenantID == actor.TenantID && len(key.Private) > 0 {
			privateKeyMaterial = base64.RawStdEncoding.EncodeToString(key.Private)
			break
		}
	}
	ledger.mu.Unlock()
	if privateKeyMaterial == "" {
		t.Fatal("test setup did not create signing key material")
	}

	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{
		Name: "customer leakage guard",
		AllowedTypes: []string{
			"artifact", "sbom", "vulnerability_scan", "vulnerability_decision", "security_review", "secret_scan", "build", "build_attestation", "release_bundle",
		},
		ExcludedFields: []string{"action_statement", "justification", "evidence_id", "evidence_ids", "internal_url"},
	})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Customer leakage guard",
		ExpiresAt:          fixedNow().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	archive, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	files := packageArchiveFiles(t, archive.Bytes)
	packageText := strings.Join(mapValues(files), "\n")
	if !strings.Contains(packageText, decision.ImpactStatement) || !strings.Contains(packageText, bundle.ManifestHash) {
		t.Fatalf("package missing expected customer-safe evidence: %s", packageText)
	}
	for _, forbidden := range []string{
		apiSecret,
		internalNote,
		internalURL,
		rawScannerPayload,
		tenantSecret,
		privateMaterialCanary,
		privateKeyMaterial,
		securityScan.PayloadRef,
		"payload_ref",
		"object://",
		"source_identity",
		"uploaded_by",
		"canonical_hash",
	} {
		if forbidden == "" {
			continue
		}
		if strings.Contains(strings.ToLower(packageText), strings.ToLower(forbidden)) {
			t.Fatalf("customer package leaked %q: %s", forbidden, packageText)
		}
	}
}

func TestSampleCustomerPackageFixtureHasNoRedactionLeakage(t *testing.T) {
	body, err := os.ReadFile("../../examples/end-to-end-release-evidence/sample-customer-package-manifest.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	text := strings.ToLower(string(body))
	for _, forbidden := range []string{
		"payload_ref",
		"object://",
		"source_identity",
		"uploaded_by",
		"api_key_secret",
		"private_key",
		"database_url",
		"raw_payload",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sample customer package fixture leaked %q: %s", forbidden, body)
		}
	}
}
