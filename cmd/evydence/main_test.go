package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCleanOperatorPathRejectsNUL(t *testing.T) {
	if _, err := cleanOperatorPath("attestation.json\x00"); err == nil {
		t.Fatal("expected NUL path rejection")
	}
}

func TestReleaseManifestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	artifactPath := dir + "/evydence-api"
	if err := os.WriteFile(artifactPath, []byte("binary"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := dir + "/manifest.json"
	if err := createReleaseArtifactManifest([]string{"--out", manifestPath, artifactPath}); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPath := dir + "/private.key"
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	sigPath := dir + "/manifest.sig.json"
	if err := signReleaseArtifactManifest([]string{"--manifest", manifestPath, "--private-key", keyPath, "--out", sigPath}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifyReleaseArtifactManifest([]string{"--manifest", manifestPath, "--signature", sigPath}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestUploadManifestPostsRequests(t *testing.T) {
	dir := t.TempDir()
	manifestPath := dir + "/upload.json"
	manifest := map[string]any{"requests": []map[string]any{{"path": "/v1/evidence", "idempotency_key": "ev-1", "payload": map[string]any{"type": "build", "title": "Build", "payload_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}}}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var saw bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = true
		if r.URL.Path != "/v1/evidence" || r.Header.Get("Idempotency-Key") != "ev-1" {
			t.Fatalf("unexpected request path=%s idem=%s", r.URL.Path, r.Header.Get("Idempotency-Key"))
		}
		_, _ = w.Write([]byte(`{"data":{"id":"ev_1"},"meta":{"api_version":"v1"}}`))
	}))
	defer server.Close()
	if err := uploadManifestRequests(t.Context(), server.Client(), []string{"--url", server.URL, "--api-key", "evy_secret", "--manifest", manifestPath}); err != nil {
		t.Fatalf("upload manifest: %v", err)
	}
	if !saw {
		t.Fatal("server did not receive upload")
	}
}

func TestValidateUploadManifestCommand(t *testing.T) {
	dir := t.TempDir()
	payloadPath := writeTestFile(t, dir+"/artifact.json", []byte(`{"name":"api","digest":"sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb","size":1}`))
	_ = payloadPath
	manifestPath := dir + "/upload.json"
	body, err := json.Marshal(map[string]any{
		"schema_version": uploadManifestSchemaVersion,
		"requests": []map[string]any{{
			"kind":            "artifact",
			"path":            "/v1/artifacts",
			"idempotency_key": "artifact-1",
			"payload_file":    "artifact.json",
		}},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return validateUploadManifestCommand([]string{"--manifest", manifestPath})
	})
	if err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
	if !strings.Contains(out, "upload manifest valid: 1 requests") {
		t.Fatalf("unexpected validate output: %s", out)
	}
}

func TestCIPreflightVerifiesAPIAndManifestWithoutSecretLeakage(t *testing.T) {
	dir := t.TempDir()
	manifestPath := dir + "/upload.json"
	body, err := json.Marshal(map[string]any{
		"schema_version": uploadManifestSchemaVersion,
		"requests": []map[string]any{{
			"kind":            "sbom",
			"path":            "/v1/sboms",
			"idempotency_key": "sbom-1",
			"payload":         map[string]any{"release_id": "rel_1", "artifact_id": "art_1", "payload": map[string]any{"bomFormat": "CycloneDX"}},
		}, {
			"kind":            "release_bundle",
			"path":            "/v1/release-bundles",
			"idempotency_key": "bundle-1",
			"payload":         map[string]any{"release_id": "rel_1"},
		}},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer evy_secret_should_not_print" {
			t.Fatalf("authorization header=%q", got)
		}
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/v1/products/prod_1":
			_, _ = w.Write([]byte(`{"data":{"id":"prod_1","tenant_id":"ten_1","name":"Payments","slug":"payments"},"meta":{"api_version":"v1"}}`))
		case "/v1/projects/proj_1":
			_, _ = w.Write([]byte(`{"data":{"id":"proj_1","tenant_id":"ten_1","product_id":"prod_1","name":"api"},"meta":{"api_version":"v1"}}`))
		case "/v1/releases/rel_1":
			_, _ = w.Write([]byte(`{"data":{"id":"rel_1","tenant_id":"ten_1","product_id":"prod_1","version":"1.0.0","state":"open"},"meta":{"api_version":"v1"}}`))
		case "/v1/artifacts/art_1":
			_, _ = w.Write([]byte(`{"data":{"id":"art_1","tenant_id":"ten_1","name":"api.tar.gz","digest":"sha256:abc"},"meta":{"api_version":"v1"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	out, err := captureStdout(t, func() error {
		return ciPreflight(t.Context(), server.Client(), []string{
			"--url", server.URL,
			"--api-key", "evy_secret_should_not_print",
			"--product-id", "prod_1",
			"--project-id", "proj_1",
			"--release-id", "rel_1",
			"--artifact-id", "art_1",
			"--manifest", manifestPath,
		})
	})
	if err != nil {
		t.Fatalf("ci preflight: %v", err)
	}
	for _, path := range []string{"/v1/products/prod_1", "/v1/projects/proj_1", "/v1/releases/rel_1", "/v1/artifacts/art_1"} {
		if !seen[path] {
			t.Fatalf("missing preflight request %s, saw %#v", path, seen)
		}
	}
	if !strings.Contains(out, "ci preflight ok") || strings.Contains(out, "evy_secret_should_not_print") {
		t.Fatalf("unsafe or incomplete output: %s", out)
	}
}

func TestCIPreflightMapsStableExitCodesAndRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	badManifest := dir + "/bad.json"
	if err := os.WriteFile(badManifest, []byte(`{"requests":[]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	err := ciPreflight(t.Context(), http.DefaultClient, []string{"--url", "https://example.test", "--api-key", "evy_secret", "--product-id", "prod_1", "--project-id", "proj_1", "--release-id", "rel_1", "--artifact-id", "art_1", "--manifest", badManifest})
	assertCLIExitCode(t, err, exitCIPreflightInvalidManifest)

	statusTests := []struct {
		status int
		code   int
	}{
		{status: http.StatusUnauthorized, code: exitCIPreflightAuthFailure},
		{status: http.StatusForbidden, code: exitCIPreflightWrongScope},
		{status: http.StatusNotFound, code: exitCIPreflightWrongTenant},
	}
	for _, tt := range statusTests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"code":"TEST","detail":"safe failure"}`, tt.status)
		}))
		err := ciPreflight(t.Context(), server.Client(), []string{"--url", server.URL, "--api-key", "evy_secret_should_not_print", "--product-id", "prod_1", "--project-id", "proj_1", "--release-id", "rel_1", "--artifact-id", "art_1", "--manifest", validPreflightManifest(t, dir)})
		server.Close()
		assertCLIExitCode(t, err, tt.code)
		if strings.Contains(err.Error(), "evy_secret_should_not_print") {
			t.Fatalf("preflight error leaked secret: %v", err)
		}
	}
	assertCLIExitCode(t, ciPreflight(t.Context(), http.DefaultClient, []string{"--url", "https://example.test"}), exitCIPreflightMissingConfig)
}

func TestUploadManifestValidationRejectsUnsafeInputs(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir+"/payload.json", []byte(`{"release_id":"rel_1"}`))
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown schema",
			body: `{"schema_version":"other","requests":[{"path":"/v1/release-bundles","idempotency_key":"k","payload":{"release_id":"rel_1"}}]}`,
			want: "schema_version",
		},
		{
			name: "unknown field",
			body: `{"schema_version":"evydence-upload-manifest.v1.0.0","unexpected":true,"requests":[{"path":"/v1/release-bundles","idempotency_key":"k","payload":{"release_id":"rel_1"}}]}`,
			want: "unknown fields",
		},
		{
			name: "both payload sources",
			body: `{"requests":[{"path":"/v1/release-bundles","idempotency_key":"k","payload":{"release_id":"rel_1"},"payload_file":"payload.json"}]}`,
			want: "exactly one",
		},
		{
			name: "payload traversal",
			body: `{"requests":[{"path":"/v1/release-bundles","idempotency_key":"k","payload_file":"../payload.json"}]}`,
			want: "inside the manifest directory",
		},
		{
			name: "kind mismatch",
			body: `{"requests":[{"kind":"sbom","path":"/v1/vex","idempotency_key":"k","payload":{"release_id":"rel_1"}}]}`,
			want: "does not allow path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestPath := dir + "/" + strings.ReplaceAll(tt.name, " ", "-") + ".json"
			if err := os.WriteFile(manifestPath, []byte(tt.body), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			err := validateUploadManifestCommand([]string{"--manifest", manifestPath})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want %q", err, tt.want)
			}
		})
	}
}

func TestImportBundleUploadPostsImport(t *testing.T) {
	dir := t.TempDir()
	bundlePath := dir + "/bundle.json"
	if err := os.WriteFile(bundlePath, []byte(`{"manifest":{"bundle_version":"evidence-bundle.v1.0.0"},"manifest_hash":"sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var saw bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = true
		if r.URL.Path != "/v1/evidence-bundles/import" || !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "import-bundle-") {
			t.Fatalf("unexpected import request path=%s idem=%s", r.URL.Path, r.Header.Get("Idempotency-Key"))
		}
		_, _ = w.Write([]byte(`{"data":{"id":"ebi_1"},"meta":{"api_version":"v1"}}`))
	}))
	defer server.Close()
	if err := uploadEvidenceBundleImport(t.Context(), server.Client(), []string{"--url", server.URL, "--api-key", "evy_secret", "--path", bundlePath}); err != nil {
		t.Fatalf("import bundle: %v", err)
	}
	if !saw {
		t.Fatal("server did not receive import")
	}
}

func TestVerifyEvidenceBundle(t *testing.T) {
	manifest := map[string]any{"bundle_version": "evidence-bundle.v1.0.0", "evidence_ids": []any{"ev_1"}}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sum := sha256.Sum256(body)
	bundleBody, err := json.Marshal(map[string]any{"manifest": manifest, "manifest_hash": "sha256:" + hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := t.TempDir() + "/bundle.json"
	if err := os.WriteFile(path, bundleBody, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := verifyEvidenceBundle(path); err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
}

func TestVerifyEvidenceBundleChecksIncludedSignature(t *testing.T) {
	manifest := map[string]any{"bundle_version": "evidence-bundle.v1.0.0", "evidence_ids": []any{"ev_1"}}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sum := sha256.Sum256(canonical)
	manifestHash := "sha256:" + hex.EncodeToString(sum[:])
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bundleBody, err := json.Marshal(map[string]any{
		"manifest":       manifest,
		"manifest_hash":  manifestHash,
		"signature_refs": []string{"sig_1"},
		"signatures": []map[string]any{{
			"id":        "sig_1",
			"key_id":    "sk_1",
			"algorithm": "Ed25519",
			"value":     base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifestHash))),
		}},
		"signing_keys": []map[string]any{{
			"id":         "sk_1",
			"algorithm":  "Ed25519",
			"status":     "active",
			"public_key": base64.RawStdEncoding.EncodeToString(pub),
		}},
	})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := t.TempDir() + "/bundle.json"
	if err := os.WriteFile(path, bundleBody, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := verifyEvidenceBundle(path); err != nil {
		t.Fatalf("verify signed bundle: %v", err)
	}
	tampered := strings.Replace(string(bundleBody), "sig_1", "sig_2", 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}
	if err := verifyEvidenceBundle(path); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("tampered signature refs err=%v", err)
	}
}

func TestVerifyCustomerPackageManifestArchiveAndBundle(t *testing.T) {
	manifest := testCustomerPackageManifest()
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	hash, err := canonicalJSONBytesHash(body)
	if err != nil {
		t.Fatalf("manifest hash: %v", err)
	}
	dir := t.TempDir()
	manifestPath := dir + "/manifest.json"
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	decisionExport := mustMarshalJSON(t, map[string]any{
		"schema_version":       "customer-vulnerability-decisions.v1.0.0",
		"package_id":           "csp_1",
		"product_id":           "prod_1",
		"release_id":           "rel_1",
		"source_manifest_hash": hash,
		"decisions":            []any{map[string]any{"id": "vd_1", "vulnerability": "CVE-2026-0001", "status": "fixed", "impact_statement": "Customer-safe impact."}},
		"assumptions":          []any{"Package-scoped decisions only."},
		"limitations":          []any{"This export does not prove legal compliance or complete vulnerability coverage."},
		"generated_at":         "2026-05-28T12:00:00Z",
	})
	archivePath := writeTestCustomerPackageArchive(t, dir+"/package.zip", body, hash, "csp_1", decisionExport)
	bundlePath := writeSignedEvidenceBundle(t, dir+"/evidence-bundle.json", []any{"ev_1"}, "sk_1")
	if err := verifyCustomerPackage([]string{
		"--manifest", manifestPath,
		"--archive", archivePath,
		"--bundle", bundlePath,
		"--hash", hash,
		"--expected-tenant-id", "ten_1",
		"--expected-product-id", "prod_1",
		"--expected-release-id", "rel_1",
		"--expected-package-id", "csp_1",
		"--expected-signing-key-id", "sk_1",
	}); err != nil {
		t.Fatalf("verify customer package: %v", err)
	}

	badArchivePath := writeTestCustomerPackageArchive(t, dir+"/package-bad.zip", body, "sha256:"+strings.Repeat("0", 64), "csp_1")
	if err := verifyCustomerPackage([]string{"--archive", badArchivePath}); err == nil || !strings.Contains(err.Error(), "manifest_hash mismatch") {
		t.Fatalf("bad archive err=%v", err)
	}
}

func TestVerifyCustomerPackageRejectsUnsafeArchiveShape(t *testing.T) {
	manifest := testCustomerPackageManifest()
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	hash, err := canonicalJSONBytesHash(body)
	if err != nil {
		t.Fatalf("manifest hash: %v", err)
	}
	dir := t.TempDir()
	unsafeArchivePath := writeCustomCustomerPackageArchive(t, dir+"/package-unsafe.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": hash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash})},
		{name: "../manifest.json", body: []byte(`{"unsafe":true}`)},
	})
	if err := verifyCustomerPackage([]string{"--archive", unsafeArchivePath}); err == nil || !strings.Contains(err.Error(), "unsafe archive entry") {
		t.Fatalf("unsafe archive err=%v", err)
	}

	duplicateArchivePath := writeCustomCustomerPackageArchive(t, dir+"/package-duplicate.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": hash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash})},
		{name: "manifest.json", body: body},
	})
	if err := verifyCustomerPackage([]string{"--archive", duplicateArchivePath}); err == nil || !strings.Contains(err.Error(), "duplicate archive entry") {
		t.Fatalf("duplicate archive err=%v", err)
	}

	unexpectedArchivePath := writeCustomCustomerPackageArchive(t, dir+"/package-unexpected.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": hash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash})},
		{name: "secrets.txt", body: []byte("not part of the customer package contract")},
	})
	if err := verifyCustomerPackage([]string{"--archive", unexpectedArchivePath}); err == nil || !strings.Contains(err.Error(), "unexpected archive entry") {
		t.Fatalf("unexpected archive err=%v", err)
	}

	undeclaredDecisionPath := writeCustomCustomerPackageArchive(t, dir+"/package-undeclared-decision.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": hash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash})},
		{name: "vulnerability-decisions.json", body: mustMarshalJSON(t, map[string]any{"source_manifest_hash": hash})},
	})
	if err := verifyCustomerPackage([]string{"--archive", undeclaredDecisionPath}); err == nil || !strings.Contains(err.Error(), "undeclared vulnerability decision export") {
		t.Fatalf("undeclared decision export err=%v", err)
	}
}

func TestVerifyCustomerPackageRejectsDuplicateJSONKeys(t *testing.T) {
	manifest := testCustomerPackageManifest()
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	dir := t.TempDir()

	duplicateManifest := []byte(strings.Replace(string(body), `"product_id":"prod_1"`, `"product_id":"prod_conflicting","product_id":"prod_1"`, 1))
	duplicateManifestHash, err := canonicalJSONBytesHash(duplicateManifest)
	if err != nil {
		t.Fatalf("duplicate manifest hash: %v", err)
	}
	duplicateManifestArchive := writeCustomCustomerPackageArchive(t, dir+"/package-duplicate-manifest-key.zip", []archiveEntry{
		{name: "manifest.json", body: duplicateManifest},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": duplicateManifestHash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": duplicateManifestHash})},
	})
	if err := verifyCustomerPackage([]string{"--archive", duplicateManifestArchive}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate manifest key err=%v", err)
	}

	hash, err := canonicalJSONBytesHash(body)
	if err != nil {
		t.Fatalf("manifest hash: %v", err)
	}
	duplicateMetadataArchive := writeCustomCustomerPackageArchive(t, dir+"/package-duplicate-metadata-key.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: []byte(`{"id":"csp_conflicting","id":"csp_1","manifest_hash":"` + hash + `"}`)},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash})},
	})
	if err := verifyCustomerPackage([]string{"--archive", duplicateMetadataArchive}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate metadata key err=%v", err)
	}

	decisionExport := mustMarshalJSON(t, map[string]any{
		"schema_version":       customerDecisionExportSchemaVersion,
		"package_id":           "csp_1",
		"product_id":           "prod_1",
		"release_id":           "rel_1",
		"source_manifest_hash": hash,
		"decisions":            []any{map[string]any{"id": "vd_1", "vulnerability": "CVE-2026-0001", "status": "fixed", "impact_statement": "Customer-safe impact."}},
		"assumptions":          []any{"Package-scoped decisions only."},
		"limitations":          []any{"This export does not prove legal compliance or complete vulnerability coverage."},
		"generated_at":         "2026-05-28T12:00:00Z",
	})
	duplicateDecisionExport := []byte(strings.Replace(string(decisionExport), `"package_id":"csp_1"`, `"package_id":"csp_conflicting","package_id":"csp_1"`, 1))
	duplicateDecisionArchive := writeCustomCustomerPackageArchive(t, dir+"/package-duplicate-decision-key.zip", []archiveEntry{
		{name: "manifest.json", body: body},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": "csp_1", "manifest_hash": hash})},
		{name: "verification.json", body: mustMarshalJSON(t, map[string]any{"package_id": "csp_1", "manifest_hash": hash, "decision_export_file": "vulnerability-decisions.json"})},
		{name: "vulnerability-decisions.json", body: duplicateDecisionExport},
	})
	if err := verifyCustomerPackage([]string{"--archive", duplicateDecisionArchive}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate decision export key err=%v", err)
	}
}

func TestValidateCustomerPackageArchiveEntryName(t *testing.T) {
	valid := []string{"manifest.json", "package.json", "verification.json", "README.txt", "report.html", "WATERMARK.txt"}
	for _, name := range valid {
		if err := validateCustomerPackageArchiveEntryName(name); err != nil {
			t.Fatalf("valid archive entry %q rejected: %v", name, err)
		}
	}
	invalid := []string{"", " ", "../manifest.json", "dir/manifest.json", "/manifest.json", `dir\manifest.json`, "manifest.json ", "evil\nname"}
	for _, name := range invalid {
		if err := validateCustomerPackageArchiveEntryName(name); err == nil {
			t.Fatalf("invalid archive entry %q accepted", name)
		}
	}
}

func TestVerifyCustomerPackageRejectsSensitiveFieldsAndMismatches(t *testing.T) {
	manifest := testCustomerPackageManifest()
	manifest["payload_ref"] = "objects/ten_1/raw-secret.json"
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := t.TempDir() + "/manifest.json"
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := verifyCustomerPackage([]string{"--manifest", path}); err == nil || !strings.Contains(err.Error(), "prohibited field payload_ref") {
		t.Fatalf("sensitive field err=%v", err)
	}

	delete(manifest, "payload_ref")
	body, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal safe manifest: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write safe manifest: %v", err)
	}
	if err := verifyCustomerPackage([]string{"--manifest", path, "--expected-tenant-id", "ten_other"}); err == nil || !strings.Contains(err.Error(), "tenant id mismatch") {
		t.Fatalf("tenant mismatch err=%v", err)
	}
}

func TestVerifyAuditChainDetectsHashTampering(t *testing.T) {
	first := testAuditEntry(t, "", 1)
	second := testAuditEntry(t, first["entry_hash"].(string), 2)
	path := t.TempDir() + "/chain.json"
	body, err := json.Marshal(map[string]any{"entries": []map[string]any{first, second}})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write chain: %v", err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	second["previous_entry_hash"] = "sha256:" + strings.Repeat("0", 64)
	body, err = json.Marshal([]map[string]any{first, second})
	if err != nil {
		t.Fatalf("marshal tampered chain: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write tampered chain: %v", err)
	}
	if err := verifyAuditChain(path); err == nil || !strings.Contains(err.Error(), "previous hash") {
		t.Fatalf("tampered chain err=%v", err)
	}
}

func TestGitHubActionsUploadBuildRequiresGitHubMetadata(t *testing.T) {
	t.Setenv("EVYDENCE_API_URL", "http://127.0.0.1")
	t.Setenv("EVYDENCE_API_KEY", "evy_secret")
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_WORKFLOW_REF", "")
	err := uploadGitHubActionsBuild(t.Context(), http.DefaultClient, []string{"--project-id", "proj_1", "--release-id", "rel_1"})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_RUN_ID") {
		t.Fatalf("err=%v, want missing GitHub metadata error", err)
	}
}

func TestGitHubActionsUploadBuildPostsBuildAndAttestationSafely(t *testing.T) {
	attestationFile, err := os.CreateTemp(t.TempDir(), "attestation-*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := attestationFile.WriteString(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"abc"}]}`); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	if err := attestationFile.Close(); err != nil {
		t.Fatalf("close attestation: %v", err)
	}
	t.Setenv("EVYDENCE_API_KEY", "evy_secret")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
	t.Setenv("GITHUB_REPOSITORY", "aatuh/evydence")
	t.Setenv("GITHUB_WORKFLOW_REF", "aatuh/evydence/.github/workflows/release.yml@refs/heads/main")
	t.Setenv("GITHUB_JOB", "build")
	t.Setenv("GITHUB_ACTOR", "aatu")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	var sawBuild, sawAttestation bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer evy_secret" {
			t.Fatalf("authorization header=%q", got)
		}
		switch r.URL.Path {
		case "/v1/builds":
			sawBuild = true
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode build: %v", err)
			}
			if payload["collector_id"] != nil {
				t.Fatalf("CLI must not submit collector_id: %#v", payload)
			}
			if payload["repository"] != "aatuh/evydence" || payload["run_id"] != "12345" || payload["oidc_subject"] != "" {
				t.Fatalf("unexpected build payload: %#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"build_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/builds/build_1/attestations":
			sawAttestation = true
			if r.Header.Get("Idempotency-Key") != "github-actions-attestation-build_1" {
				t.Fatalf("unexpected attestation idempotency key: %s", r.Header.Get("Idempotency-Key"))
			}
			_, _ = w.Write([]byte(`{"data":{"id":"att_1"},"meta":{"api_version":"v1"}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	err = uploadGitHubActionsBuild(t.Context(), server.Client(), []string{
		"--url", server.URL,
		"--api-key", "evy_secret",
		"--project-id", "proj_1",
		"--release-id", "rel_1",
		"--artifact-id", "art_1",
		"--artifact-digest", "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"--attestation-path", attestationFile.Name(),
		"--started-at", "2026-05-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !sawBuild || !sawAttestation {
		t.Fatalf("sawBuild=%v sawAttestation=%v", sawBuild, sawAttestation)
	}
}

func TestReleaseUploadEvidenceDryRunValidatesFilesAndPrintsNextSteps(t *testing.T) {
	dir := t.TempDir()
	artifactPath := writeTestFile(t, dir+"/api.tar.gz", []byte("artifact"))
	sbomPath := writeTestFile(t, dir+"/sbom.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:github/acme/api@abc"}]}`))
	scanPath := writeTestFile(t, dir+"/scan.json", []byte(`{"findings":[]}`))
	vexPath := writeTestFile(t, dir+"/vex.json", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-27T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:github/acme/api@abc"}],"status":"not_affected","justification":"component_not_present","impact_statement":"not shipped","action_statement":"none"}]}`))
	t.Setenv("EVYDENCE_API_KEY", "evy_secret_should_not_print")

	out, err := captureStdout(t, func() error {
		return uploadReleaseEvidence(t.Context(), http.DefaultClient, []string{
			"--dry-run",
			"--product-id", "prod_1",
			"--release-id", "rel_1",
			"--artifact-id", "art_1",
			"--artifact", artifactPath,
			"--sbom", sbomPath,
			"--scan", scanPath,
			"--scan-scanner", "generic",
			"--target-ref", "pkg:github/acme/api@abc",
			"--vex", vexPath,
		})
	})
	if err != nil {
		t.Fatalf("dry-run upload: %v", err)
	}
	for _, expected := range []string{"/v1/sboms", "/v1/vulnerability-scans", "/v1/vex", "/v1/release-bundles", "/v1/reports/release-readiness?release_id=rel_1"} {
		if !strings.Contains(out, expected) {
			t.Fatalf("dry-run output missing %q:\n%s", expected, out)
		}
	}
	if strings.Contains(out, "evy_secret_should_not_print") {
		t.Fatalf("dry-run output leaked API key: %s", out)
	}
}

func TestReleaseUploadEvidenceCreatesMissingResourcesAndUploads(t *testing.T) {
	dir := t.TempDir()
	artifactPath := writeTestFile(t, dir+"/api.tar.gz", []byte("artifact"))
	sbomPath := writeTestFile(t, dir+"/sbom.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:github/acme/api@abc"}]}`))
	scanPath := writeTestFile(t, dir+"/scan.json", []byte(`{"scanner":"generic","findings":[]}`))
	vexPath := writeTestFile(t, dir+"/vex.json", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-27T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:github/acme/api@abc"}],"status":"fixed","justification":"fixed","impact_statement":"patched","action_statement":"upgrade"}]}`))
	seen := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer evy_secret" {
			t.Fatalf("authorization header=%q", got)
		}
		if !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "one-shot-") {
			t.Fatalf("idempotency key=%q", r.Header.Get("Idempotency-Key"))
		}
		seen = append(seen, r.URL.Path)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload for %s: %v", r.URL.Path, err)
		}
		switch r.URL.Path {
		case "/v1/products":
			if payload["name"] != "Payments" || payload["slug"] != "payments" {
				t.Fatalf("product payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"prod_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/releases":
			if payload["product_id"] != "prod_1" || payload["version"] != "1.0.0" {
				t.Fatalf("release payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"rel_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/artifacts":
			if payload["name"] != "api.tar.gz" || !strings.HasPrefix(payload["digest"].(string), "sha256:") {
				t.Fatalf("artifact payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"art_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/sboms":
			if payload["release_id"] != "rel_1" || payload["artifact_id"] != "art_1" {
				t.Fatalf("sbom payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"sbom_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/vulnerability-scans":
			if payload["release_id"] != "rel_1" || payload["target_ref"] != "pkg:github/acme/api@abc" {
				t.Fatalf("scan payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"scan_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/vex":
			if payload["release_id"] != "rel_1" || payload["artifact_id"] != "art_1" {
				t.Fatalf("vex payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"vex_1"},"meta":{"api_version":"v1"}}`))
		case "/v1/release-bundles":
			if payload["release_id"] != "rel_1" {
				t.Fatalf("bundle payload=%#v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"id":"bundle_1"},"meta":{"api_version":"v1"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	if err := uploadReleaseEvidence(t.Context(), server.Client(), []string{
		"--url", server.URL,
		"--api-key", "evy_secret",
		"--create-product",
		"--product-name", "Payments",
		"--product-slug", "payments",
		"--create-release",
		"--release-version", "1.0.0",
		"--create-artifact",
		"--artifact", artifactPath,
		"--sbom", sbomPath,
		"--scan", scanPath,
		"--target-ref", "pkg:github/acme/api@abc",
		"--vex", vexPath,
		"--idempotency-prefix", "one-shot",
	}); err != nil {
		t.Fatalf("upload evidence: %v", err)
	}
	want := []string{"/v1/products", "/v1/releases", "/v1/artifacts", "/v1/sboms", "/v1/vulnerability-scans", "/v1/vex", "/v1/release-bundles"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("paths=%v want=%v", seen, want)
	}
}

func TestReleaseUploadEvidenceRequiresExplicitCreateFlags(t *testing.T) {
	dir := t.TempDir()
	sbomPath := writeTestFile(t, dir+"/sbom.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`))
	err := uploadReleaseEvidence(t.Context(), http.DefaultClient, []string{"--dry-run", "--sbom", sbomPath})
	if err == nil || !strings.Contains(err.Error(), "--release-id") {
		t.Fatalf("missing release err=%v", err)
	}
	artifactPath := writeTestFile(t, dir+"/api.tar.gz", []byte("artifact"))
	err = uploadReleaseEvidence(t.Context(), http.DefaultClient, []string{"--dry-run", "--release-id", "rel_1", "--artifact", artifactPath, "--sbom", sbomPath})
	if err == nil || !strings.Contains(err.Error(), "--artifact-id") {
		t.Fatalf("missing artifact err=%v", err)
	}
}

func TestUsageRunAndManifestVerificationHelpers(t *testing.T) {
	if err := usage(); err == nil || !strings.Contains(err.Error(), "evydence hash") {
		t.Fatalf("usage err=%v", err)
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("empty run err=%v", err)
	}
	if err := run([]string{"unknown"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("unknown run err=%v", err)
	}

	manifest := map[string]any{"name": "release", "artifacts": []any{}}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sum := sha256.Sum256(canonical)
	path := t.TempDir() + "/manifest.json"
	if err := os.WriteFile(path, []byte(`{"artifacts":[],"name":"release"}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := verifyManifest(path, "sha256:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	if err := verifyManifest(path, hex.EncodeToString(sum[:])); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("bad expected hash err=%v", err)
	}
	if err := verifyManifest(path, "sha256:"+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("hash mismatch err=%v", err)
	}
}

func writeTestFile(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	runErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = old
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	return string(out), runErr
}

func TestGenerateReleaseSigningKeyWritesBase64Keys(t *testing.T) {
	dir := t.TempDir()
	privatePath := dir + "/private.key"
	publicPath := dir + "/public.key"
	if err := generateReleaseSigningKey([]string{"--private-out", privatePath, "--public-out", publicPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	privateKey, err := readBase64File(privatePath, ed25519.PrivateKeySize)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	publicKey, err := readBase64File(publicPath, ed25519.PublicKeySize)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if !ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(publicKey)) {
		t.Fatal("public key does not match private key")
	}
}

func TestSafeAPIErrorUsesProblemCodeWithoutLeakingRawFallbackBody(t *testing.T) {
	err := safeAPIError(http.StatusConflict, []byte(`{"code":"IDEMPOTENCY_KEY_REUSED","detail":"same key changed content"}`))
	if err == nil || !strings.Contains(err.Error(), "IDEMPOTENCY_KEY_REUSED") || !strings.Contains(err.Error(), "same key changed content") {
		t.Fatalf("problem error=%v", err)
	}
	err = safeAPIError(http.StatusForbidden, []byte(`bearer token secret`))
	if err == nil || !strings.Contains(err.Error(), "Forbidden") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("fallback error leaked body or missed status text: %v", err)
	}
}

func TestResponseAndURLHelpersValidateInputs(t *testing.T) {
	if got, err := cleanAPIURL("https://example.test/api?token=secret#frag"); err != nil || got != "https://example.test/api" {
		t.Fatalf("cleanAPIURL got=%q err=%v", got, err)
	}
	if _, err := cleanAPIURL("file:///tmp/evydence"); err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("file URL err=%v", err)
	}
	if _, err := responseDataID([]byte(`{"data":{}}`)); err == nil || !strings.Contains(err.Error(), "data.id") {
		t.Fatalf("missing id err=%v", err)
	}
	if _, err := responseDataID([]byte(`not-json`)); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if got := atoiDefault(" 3 ", 1); got != 3 {
		t.Fatalf("atoi configured = %d", got)
	}
	if got := atoiDefault("nope", 1); got != 1 {
		t.Fatalf("atoi fallback = %d", got)
	}
	if _, err := cleanOperatorPath("\x00"); err == nil {
		t.Fatal("expected NUL path error")
	}
}

func TestRunCoversHashBundleAndReleaseCommands(t *testing.T) {
	dir := t.TempDir()
	artifact := dir + "/artifact.bin"
	if err := os.WriteFile(artifact, []byte("binary"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if err := run([]string{"hash", artifact}); err != nil {
		t.Fatalf("run hash: %v", err)
	}
	manifest := dir + "/manifest.json"
	if err := run([]string{"release", "manifest", "--out", manifest, artifact}); err != nil {
		t.Fatalf("run release manifest: %v", err)
	}
	privateKey := dir + "/private.key"
	publicKey := dir + "/public.key"
	if err := run([]string{"release", "keygen", "--private-out", privateKey, "--public-out", publicKey}); err != nil {
		t.Fatalf("run release keygen: %v", err)
	}
	signature := dir + "/manifest.sig.json"
	if err := run([]string{"release", "sign", "--manifest", manifest, "--private-key", privateKey, "--out", signature}); err != nil {
		t.Fatalf("run release sign: %v", err)
	}
	if err := run([]string{"release", "verify", "--manifest", manifest, "--signature", signature}); err != nil {
		t.Fatalf("run release verify: %v", err)
	}
	var decoded map[string]any
	canonical, hash, err := canonicalFileHash(manifest)
	if err != nil {
		t.Fatalf("canonical hash: %v", err)
	}
	if err := json.Unmarshal(canonical, &decoded); err != nil || decoded["schema_version"] == "" {
		t.Fatalf("canonical manifest decode=%#v err=%v", decoded, err)
	}
	if err := run([]string{"verify-manifest", manifest, "--hash", hash}); err != nil {
		t.Fatalf("run verify manifest: %v", err)
	}
	bundleManifest := map[string]any{"schema_version": "evidence-bundle.v1.0.0", "evidence_ids": []any{"ev_1"}}
	bundleBody, err := json.Marshal(bundleManifest)
	if err != nil {
		t.Fatalf("marshal bundle manifest: %v", err)
	}
	sum := sha256.Sum256(bundleBody)
	bundlePath := dir + "/bundle.json"
	body, err := json.Marshal(map[string]any{"manifest": bundleManifest, "manifest_hash": "sha256:" + hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if err := os.WriteFile(bundlePath, body, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := run([]string{"verify-evidence-bundle", bundlePath}); err != nil {
		t.Fatalf("run verify evidence bundle: %v", err)
	}
	customerManifestBody, err := json.Marshal(testCustomerPackageManifest())
	if err != nil {
		t.Fatalf("marshal customer package manifest: %v", err)
	}
	customerManifest := dir + "/customer-package.json"
	if err := os.WriteFile(customerManifest, customerManifestBody, 0o600); err != nil {
		t.Fatalf("write customer package manifest: %v", err)
	}
	if err := run([]string{"package", "verify", "--manifest", customerManifest}); err != nil {
		t.Fatalf("run package verify: %v", err)
	}
	chainPath := dir + "/chain.json"
	entry := testAuditEntry(t, "", 1)
	chainBody, err := json.Marshal([]map[string]any{entry})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	if err := os.WriteFile(chainPath, chainBody, 0o600); err != nil {
		t.Fatalf("write chain: %v", err)
	}
	if err := run([]string{"verify-audit-chain", chainPath}); err != nil {
		t.Fatalf("run verify audit chain: %v", err)
	}
}

func TestRunUploadCommandsAndGitHubUsageBranches(t *testing.T) {
	if err := run([]string{"github-actions"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("github usage err=%v", err)
	}
	if err := run([]string{"import-bundle"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("import usage err=%v", err)
	}
	if err := run([]string{"upload"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("upload usage err=%v", err)
	}
	if err := run([]string{"release", "unknown"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("release usage err=%v", err)
	}
}

func testAuditEntry(t *testing.T, previous string, sequence int64) map[string]any {
	t.Helper()
	entry := map[string]any{
		"tenant_id":            "ten_1",
		"sequence":             sequence,
		"entry_type":           "evidence.created",
		"subject_type":         "evidence",
		"subject_id":           "ev_1",
		"actor_type":           "api_key",
		"actor_id":             "key_1",
		"occurred_at":          "2026-05-28T12:00:00Z",
		"payload_hash":         "sha256:" + strings.Repeat("a", 64),
		"previous_entry_hash":  previous,
		"signature_ref":        "",
		"schema_version":       "audit-chain-entry.v1.0.0",
		"id":                   "ace_1",
		"canonical_entry_hash": "",
		"entry_hash":           "",
	}
	canonical, err := auditEntryCanonicalHash(offlineAuditChainEntry{
		TenantID:          entry["tenant_id"].(string),
		Sequence:          sequence,
		EntryType:         entry["entry_type"].(string),
		SubjectType:       entry["subject_type"].(string),
		SubjectID:         entry["subject_id"].(string),
		ActorType:         entry["actor_type"].(string),
		ActorID:           entry["actor_id"].(string),
		OccurredAt:        mustParseTime(t, entry["occurred_at"].(string)),
		PayloadHash:       entry["payload_hash"].(string),
		PreviousEntryHash: previous,
		SignatureRef:      entry["signature_ref"].(string),
		SchemaVersion:     entry["schema_version"].(string),
	})
	if err != nil {
		t.Fatalf("canonical audit hash: %v", err)
	}
	entry["canonical_entry_hash"] = canonical
	entry["entry_hash"] = hashString(previous + "\n" + canonical)
	return entry
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return parsed
}

func testCustomerPackageManifest() map[string]any {
	return map[string]any{
		"schema_version":        "customer-security-package.v2.0.0",
		"package_version":       "customer-security-package.v2.0.0",
		"package_id":            "csp_1",
		"id":                    "csp_1",
		"title":                 "Customer package",
		"generated_at":          "2026-05-28T12:00:00Z",
		"tenant":                map[string]any{"id": "ten_1", "name": "Tenant"},
		"product":               map[string]any{"id": "prod_1", "name": "Payments API"},
		"product_id":            "prod_1",
		"release":               map[string]any{"id": "rel_1", "product_id": "prod_1", "version": "1.0.0", "state": "approved", "created_at": "2026-05-28T12:00:00Z"},
		"release_id":            "rel_1",
		"redaction_profile_id":  "rp_1",
		"redaction_profile":     map[string]any{"id": "rp_1", "name": "customer_safe", "allowed_types": []any{"artifact", "release_bundle"}, "excluded_fields": []any{"payload_ref"}, "schema_version": "redaction-profile.v1.0.0"},
		"evidence_ids":          []any{"ev_1"},
		"artifact_digests":      []any{map[string]any{"id": "art_1", "name": "artifact.tar.gz", "media_type": "application/gzip", "size": 123, "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "created_at": "2026-05-28T12:00:00Z"}},
		"readiness_summary":     map[string]any{"result": "passed", "checks": []any{}, "gaps": []any{}, "limitations": []any{"Readiness is derived from package-scoped evidence only."}},
		"verification_material": map[string]any{"hash_algorithm": "sha256", "canonicalization": "canonicalization-profile.v1.0.0", "manifest_hash_field": "manifest_hash", "release_bundles": []any{map[string]any{"id": "rb_1", "manifest_hash": "sha256:" + strings.Repeat("b", 64), "signature_refs": []any{"sig_1"}}}},
		"limitations":           []any{"Package contents are scoped by product, release, redaction profile, and package expiry."},
		"non_claims":            []any{"This package supports technical evidence review and compliance readiness only."},
	}
}

func writeTestCustomerPackageArchive(t *testing.T, path string, manifest []byte, manifestHash, packageID string, decisionExport ...[]byte) string {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	zw := zip.NewWriter(file)
	verification := map[string]any{"package_id": packageID, "manifest_hash": manifestHash, "manifest_file": "manifest.json"}
	if len(decisionExport) > 0 {
		verification["decision_export_file"] = "vulnerability-decisions.json"
	}
	entries := []struct {
		name string
		body []byte
	}{
		{name: "manifest.json", body: manifest},
		{name: "package.json", body: mustMarshalJSON(t, map[string]any{"id": packageID, "manifest_hash": manifestHash})},
		{name: "verification.json", body: mustMarshalJSON(t, verification)},
	}
	if len(decisionExport) > 0 {
		entries = append(entries, struct {
			name string
			body []byte
		}{name: "vulnerability-decisions.json", body: decisionExport[0]})
	}
	for _, entry := range entries {
		writer, err := zw.Create(entry.name)
		if err != nil {
			t.Fatalf("create archive entry: %v", err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatalf("write archive entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}

type archiveEntry struct {
	name string
	body []byte
}

func writeCustomCustomerPackageArchive(t *testing.T, path string, entries []archiveEntry) string {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	zw := zip.NewWriter(file)
	for _, entry := range entries {
		writer, err := zw.Create(entry.name)
		if err != nil {
			t.Fatalf("create archive entry: %v", err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatalf("write archive entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}

func writeSignedEvidenceBundle(t *testing.T, path string, evidenceIDs []any, keyID string) string {
	t.Helper()
	manifest := map[string]any{"bundle_version": "evidence-bundle.v1.0.0", "evidence_ids": evidenceIDs}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal bundle manifest: %v", err)
	}
	sum := sha256.Sum256(canonical)
	manifestHash := "sha256:" + hex.EncodeToString(sum[:])
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bundle key: %v", err)
	}
	body := mustMarshalJSON(t, map[string]any{
		"manifest":       manifest,
		"manifest_hash":  manifestHash,
		"signature_refs": []any{"sig_1"},
		"signatures": []any{map[string]any{
			"id":         "sig_1",
			"key_id":     keyID,
			"algorithm":  "Ed25519",
			"value":      base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifestHash))),
			"created_at": "2026-05-28T12:00:00Z",
		}},
		"signing_keys": []any{map[string]any{
			"id":         keyID,
			"algorithm":  "Ed25519",
			"status":     "active",
			"public_key": base64.RawStdEncoding.EncodeToString(pub),
		}},
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write evidence bundle: %v", err)
	}
	return path
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return body
}

func validPreflightManifest(t *testing.T, dir string) string {
	t.Helper()
	path := dir + "/preflight-valid.json"
	body := mustMarshalJSON(t, map[string]any{
		"schema_version": uploadManifestSchemaVersion,
		"requests": []map[string]any{{
			"kind":            "sbom",
			"path":            "/v1/sboms",
			"idempotency_key": "sbom-1",
			"payload":         map[string]any{"release_id": "rel_1", "artifact_id": "art_1", "payload": map[string]any{"bomFormat": "CycloneDX"}},
		}},
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write preflight manifest: %v", err)
	}
	return path
}

func assertCLIExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected exit code %d, got nil", want)
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(err, &exitErr) {
		t.Fatalf("err=%v does not expose exit code %d", err, want)
	}
	if got := exitErr.ExitCode(); got != want {
		t.Fatalf("exit code=%d want=%d err=%v", got, want, err)
	}
}
