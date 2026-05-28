package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
