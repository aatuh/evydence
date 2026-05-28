package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "hash":
		if len(args) != 2 {
			return usage()
		}
		digest, err := hashFile(args[1])
		if err != nil {
			return err
		}
		fmt.Println(digest)
		return nil
	case "verify-manifest":
		if len(args) != 4 || args[2] != "--hash" {
			return usage()
		}
		return verifyManifest(args[1], args[3])
	case "verify-evidence-bundle":
		if len(args) != 2 {
			return usage()
		}
		return verifyEvidenceBundle(args[1])
	case "verify-audit-chain":
		if len(args) != 2 {
			return usage()
		}
		return verifyAuditChain(args[1])
	case "github-actions":
		if len(args) < 2 || args[1] != "upload-build" {
			return usage()
		}
		return uploadGitHubActionsBuild(context.Background(), http.DefaultClient, args[2:])
	case "import-bundle":
		if len(args) < 2 || args[1] != "upload" {
			return usage()
		}
		return uploadEvidenceBundleImport(context.Background(), http.DefaultClient, args[2:])
	case "upload":
		if len(args) < 2 || args[1] != "manifest" {
			return usage()
		}
		return uploadManifestRequests(context.Background(), http.DefaultClient, args[2:])
	case "release":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "manifest":
			return createReleaseArtifactManifest(args[2:])
		case "sign":
			return signReleaseArtifactManifest(args[2:])
		case "verify":
			return verifyReleaseArtifactManifest(args[2:])
		case "keygen":
			return generateReleaseSigningKey(args[2:])
		default:
			return usage()
		}
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: evydence hash <file> | evydence verify-manifest <manifest.json> --hash sha256:<hex> | evydence verify-evidence-bundle <bundle.json> | evydence verify-audit-chain <chain.json> | evydence github-actions upload-build ... | evydence import-bundle upload ... | evydence upload manifest ... | evydence release manifest|sign|verify|keygen")
}

func hashFile(path string) (string, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return "", err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified file and does not use elevated privileges.
	file, err := os.Open(cleaned)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func verifyManifest(path, expected string) error {
	expected = strings.TrimSpace(expected)
	if !strings.HasPrefix(expected, "sha256:") {
		return errors.New("expected hash must use sha256:<hex>")
	}
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified manifest and does not use elevated privileges.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return fmt.Errorf("manifest is not JSON: %w", err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("manifest hash mismatch: got %s want %s", got, expected)
	}
	fmt.Println("manifest hash verified")
	return nil
}

func verifyEvidenceBundle(path string) error {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified bundle file.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	var bundle struct {
		Manifest      map[string]any      `json:"manifest"`
		ManifestHash  string              `json:"manifest_hash"`
		SignatureRefs []string            `json:"signature_refs"`
		Signatures    []offlineSignature  `json:"signatures"`
		SigningKeys   []offlineSigningKey `json:"signing_keys"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		return errors.New("evidence bundle is not JSON")
	}
	if len(bundle.Manifest) == 0 || strings.TrimSpace(bundle.ManifestHash) == "" {
		return errors.New("evidence bundle missing manifest or manifest_hash")
	}
	canonical, err := json.Marshal(bundle.Manifest)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(canonical, &normalized); err != nil {
		return err
	}
	canonical, err = json.Marshal(normalized)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != bundle.ManifestHash {
		return fmt.Errorf("evidence bundle hash mismatch: got %s want %s", got, bundle.ManifestHash)
	}
	if err := verifyOfflineSignatures(bundle.ManifestHash, bundle.SignatureRefs, bundle.Signatures, bundle.SigningKeys); err != nil {
		return err
	}
	if len(bundle.Signatures) > 0 || len(bundle.SigningKeys) > 0 {
		fmt.Println("evidence bundle manifest and signature verified")
		return nil
	}
	fmt.Println("evidence bundle manifest verified")
	return nil
}

type offlineSignature struct {
	ID        string    `json:"id"`
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type offlineSigningKey struct {
	ID        string     `json:"id"`
	Algorithm string     `json:"algorithm"`
	Status    string     `json:"status"`
	PublicKey string     `json:"public_key"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type offlineAuditChainEntry struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	Sequence           int64     `json:"sequence"`
	EntryType          string    `json:"entry_type"`
	SubjectType        string    `json:"subject_type"`
	SubjectID          string    `json:"subject_id"`
	ActorType          string    `json:"actor_type"`
	ActorID            string    `json:"actor_id"`
	OccurredAt         time.Time `json:"occurred_at"`
	PayloadHash        string    `json:"payload_hash"`
	PreviousEntryHash  string    `json:"previous_entry_hash"`
	SignatureRef       string    `json:"signature_ref"`
	SchemaVersion      string    `json:"schema_version"`
	CanonicalEntryHash string    `json:"canonical_entry_hash"`
	EntryHash          string    `json:"entry_hash"`
}

func verifyAuditChain(path string) error {
	body, err := readFileStrict(path)
	if err != nil {
		return err
	}
	entries, err := decodeAuditChain(body)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("audit chain contains no entries")
	}
	previous := ""
	for i, entry := range entries {
		if entry.Sequence != int64(i+1) {
			return fmt.Errorf("audit chain sequence mismatch at entry %d", i+1)
		}
		if entry.PreviousEntryHash != previous {
			return fmt.Errorf("audit chain previous hash mismatch at entry %d", i+1)
		}
		canonical, err := auditEntryCanonicalHash(entry)
		if err != nil {
			return err
		}
		if entry.CanonicalEntryHash != canonical {
			return fmt.Errorf("audit chain canonical hash mismatch at entry %d", i+1)
		}
		if hashString(previous+"\n"+entry.CanonicalEntryHash) != entry.EntryHash {
			return fmt.Errorf("audit chain entry hash mismatch at entry %d", i+1)
		}
		previous = entry.EntryHash
	}
	fmt.Println("audit chain verified")
	return nil
}

func decodeAuditChain(body []byte) ([]offlineAuditChainEntry, error) {
	var envelope struct {
		Entries []offlineAuditChainEntry `json:"entries"`
		Chain   []offlineAuditChainEntry `json:"chain"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		if len(envelope.Entries) > 0 {
			return envelope.Entries, nil
		}
		if len(envelope.Chain) > 0 {
			return envelope.Chain, nil
		}
	}
	var entries []offlineAuditChainEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, errors.New("audit chain is not JSON array or entries envelope")
	}
	return entries, nil
}

func auditEntryCanonicalHash(entry offlineAuditChainEntry) (string, error) {
	if strings.TrimSpace(entry.TenantID) == "" || entry.Sequence <= 0 || strings.TrimSpace(entry.EntryType) == "" || strings.TrimSpace(entry.SubjectType) == "" || strings.TrimSpace(entry.SubjectID) == "" || strings.TrimSpace(entry.ActorType) == "" || strings.TrimSpace(entry.SchemaVersion) == "" || entry.OccurredAt.IsZero() {
		return "", errors.New("audit chain entry missing required fields")
	}
	return canonicalJSONHash(map[string]any{
		"tenant_id":           entry.TenantID,
		"sequence":            entry.Sequence,
		"entry_type":          entry.EntryType,
		"subject_type":        entry.SubjectType,
		"subject_id":          entry.SubjectID,
		"actor_type":          entry.ActorType,
		"actor_id":            entry.ActorID,
		"occurred_at":         entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		"payload_hash":        entry.PayloadHash,
		"previous_entry_hash": entry.PreviousEntryHash,
		"signature_ref":       entry.SignatureRef,
		"schema_version":      entry.SchemaVersion,
	})
}

func verifyOfflineSignatures(payloadHash string, refs []string, signatures []offlineSignature, keys []offlineSigningKey) error {
	if len(signatures) == 0 && len(keys) == 0 {
		return nil
	}
	if strings.TrimSpace(payloadHash) == "" || len(refs) == 0 || len(signatures) == 0 || len(keys) == 0 {
		return errors.New("offline signature material is incomplete")
	}
	keyByID := map[string]offlineSigningKey{}
	for _, key := range keys {
		if key.ID != "" {
			keyByID[key.ID] = key
		}
	}
	signatureByID := map[string]offlineSignature{}
	for _, signature := range signatures {
		if signature.ID != "" {
			signatureByID[signature.ID] = signature
		}
	}
	for _, ref := range refs {
		signature, ok := signatureByID[strings.TrimSpace(ref)]
		if !ok || signature.Algorithm != "Ed25519" {
			continue
		}
		key, ok := keyByID[signature.KeyID]
		if !ok || key.Algorithm != "Ed25519" {
			continue
		}
		if key.Status == "revoked" && (key.RevokedAt == nil || signature.CreatedAt.IsZero() || signature.CreatedAt.After(*key.RevokedAt)) {
			continue
		}
		pub, err := decodeBase64Flexible(key.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		value, err := decodeBase64Flexible(signature.Value)
		if err != nil || len(value) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), []byte(payloadHash), value) {
			return nil
		}
	}
	return errors.New("offline signature verification failed")
}

func cleanOperatorPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("file path is required")
	}
	if strings.Contains(path, "\x00") {
		return "", errors.New("file path contains a NUL byte")
	}
	return filepath.Clean(path), nil
}

func uploadGitHubActionsBuild(ctx context.Context, client *http.Client, args []string) error {
	fs := flag.NewFlagSet("github-actions upload-build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		apiURL          = fs.String("url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
		apiKey          = fs.String("api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
		projectID       = fs.String("project-id", "", "Evydence project ID")
		releaseID       = fs.String("release-id", "", "Evydence release ID")
		artifactID      = fs.String("artifact-id", "", "Evydence artifact ID")
		artifactDigest  = fs.String("artifact-digest", "", "artifact digest")
		attestationPath = fs.String("attestation-path", "", "DSSE attestation JSON path")
		status          = fs.String("status", envDefault("EVYDENCE_BUILD_STATUS", "passed"), "build status")
		startedAt       = fs.String("started-at", envDefault("EVYDENCE_BUILD_STARTED_AT", time.Now().UTC().Format(time.RFC3339)), "build start time")
		finishedAt      = fs.String("finished-at", strings.TrimSpace(os.Getenv("EVYDENCE_BUILD_FINISHED_AT")), "build finish time")
		parametersHash  = fs.String("parameters-hash", "", "build parameters hash")
		environmentHash = fs.String("environment-hash", "", "build environment hash")
		oidcSubject     = fs.String("oidc-subject", strings.TrimSpace(os.Getenv("EVYDENCE_GITHUB_OIDC_SUBJECT")), "captured GitHub OIDC subject")
	)
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*apiKey) == "" || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*releaseID) == "" {
		return usage()
	}
	if (*artifactID == "") != (*artifactDigest == "") {
		return errors.New("--artifact-id and --artifact-digest must be provided together")
	}
	started, err := time.Parse(time.RFC3339, strings.TrimSpace(*startedAt))
	if err != nil {
		return errors.New("--started-at must use RFC3339")
	}
	var finished *time.Time
	if strings.TrimSpace(*finishedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*finishedAt))
		if err != nil {
			return errors.New("--finished-at must use RFC3339")
		}
		finished = &parsed
	}
	outputs := []map[string]string{}
	if strings.TrimSpace(*artifactID) != "" {
		outputs = append(outputs, map[string]string{"artifact_id": strings.TrimSpace(*artifactID), "digest": strings.TrimSpace(*artifactDigest)})
	}
	runID := envRequired("GITHUB_RUN_ID")
	runAttempt := envDefault("GITHUB_RUN_ATTEMPT", "1")
	commitSHA := envRequired("GITHUB_SHA")
	repository := envRequired("GITHUB_REPOSITORY")
	workflowRef := envRequired("GITHUB_WORKFLOW_REF")
	if runID == "" || commitSHA == "" || repository == "" || workflowRef == "" {
		return errors.New("GITHUB_RUN_ID, GITHUB_SHA, GITHUB_REPOSITORY, and GITHUB_WORKFLOW_REF are required")
	}
	payload := map[string]any{
		"project_id":       strings.TrimSpace(*projectID),
		"release_id":       strings.TrimSpace(*releaseID),
		"provider":         "github_actions",
		"commit_sha":       commitSHA,
		"repository":       repository,
		"workflow_ref":     workflowRef,
		"run_id":           runID,
		"run_attempt":      atoiDefault(runAttempt, 1),
		"job_id":           strings.TrimSpace(os.Getenv("GITHUB_JOB")),
		"actor":            strings.TrimSpace(os.Getenv("GITHUB_ACTOR")),
		"ref":              strings.TrimSpace(os.Getenv("GITHUB_REF")),
		"oidc_subject":     strings.TrimSpace(*oidcSubject),
		"status":           strings.TrimSpace(*status),
		"started_at":       started.UTC().Format(time.RFC3339),
		"finished_at":      finished,
		"parameters_hash":  strings.TrimSpace(*parametersHash),
		"environment_hash": strings.TrimSpace(*environmentHash),
		"outputs":          outputs,
	}
	body, err := postEvydence(ctx, client, *apiURL, *apiKey, "/v1/builds", "github-actions-build-"+runID+"-"+runAttempt, payload)
	if err != nil {
		return err
	}
	buildID, err := responseDataID(body)
	if err != nil {
		return err
	}
	fmt.Println("build uploaded: " + buildID)
	if strings.TrimSpace(*attestationPath) == "" {
		return nil
	}
	cleaned, err := cleanOperatorPath(*attestationPath)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified attestation file.
	attestation, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	body, err = postRawEvydence(ctx, client, *apiURL, *apiKey, "/v1/builds/"+buildID+"/attestations", "github-actions-attestation-"+buildID, attestation)
	if err != nil {
		return err
	}
	attestationID, err := responseDataID(body)
	if err != nil {
		return err
	}
	fmt.Println("attestation uploaded: " + attestationID)
	return nil
}

func uploadEvidenceBundleImport(ctx context.Context, client *http.Client, args []string) error {
	fs := flag.NewFlagSet("import-bundle upload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apiURL := fs.String("url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
	apiKey := fs.String("api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
	path := fs.String("path", "", "evidence bundle JSON path")
	idem := fs.String("idempotency-key", "", "idempotency key")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*apiKey) == "" || strings.TrimSpace(*path) == "" {
		return usage()
	}
	cleaned, err := cleanOperatorPath(*path)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified import bundle.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*idem) == "" {
		digest := sha256.Sum256(body)
		*idem = "import-bundle-" + hex.EncodeToString(digest[:8])
	}
	response, err := postRawEvydence(ctx, client, *apiURL, *apiKey, "/v1/evidence-bundles/import", *idem, body)
	if err != nil {
		return err
	}
	id, err := responseDataID(response)
	if err != nil {
		return err
	}
	fmt.Println("evidence bundle import recorded: " + id)
	return nil
}

func uploadManifestRequests(ctx context.Context, client *http.Client, args []string) error {
	fs := flag.NewFlagSet("upload manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apiURL := fs.String("url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
	apiKey := fs.String("api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
	manifestPath := fs.String("manifest", "", "upload manifest JSON path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*apiKey) == "" || strings.TrimSpace(*manifestPath) == "" {
		return usage()
	}
	cleaned, err := cleanOperatorPath(*manifestPath)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified upload manifest.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	var manifest struct {
		Requests []struct {
			Path           string          `json:"path"`
			IdempotencyKey string          `json:"idempotency_key"`
			Payload        json.RawMessage `json:"payload"`
			PayloadFile    string          `json:"payload_file"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return errors.New("upload manifest is not valid JSON")
	}
	if len(manifest.Requests) == 0 || len(manifest.Requests) > 100 {
		return errors.New("upload manifest must contain 1-100 requests")
	}
	baseDir := filepath.Dir(cleaned)
	for i, req := range manifest.Requests {
		path := strings.TrimSpace(req.Path)
		idem := strings.TrimSpace(req.IdempotencyKey)
		if !strings.HasPrefix(path, "/v1/") || idem == "" {
			return fmt.Errorf("upload request %d missing /v1 path or idempotency key", i)
		}
		payload := req.Payload
		if strings.TrimSpace(req.PayloadFile) != "" {
			payloadPath, err := cleanOperatorPath(filepath.Join(baseDir, req.PayloadFile))
			if err != nil {
				return err
			}
			// #nosec G304,G703 -- payload files are local operator-selected files referenced by the manifest.
			payload, err = os.ReadFile(payloadPath)
			if err != nil {
				return err
			}
		}
		if len(bytes.TrimSpace(payload)) == 0 {
			return fmt.Errorf("upload request %d has empty payload", i)
		}
		response, err := postRawEvydence(ctx, client, *apiURL, *apiKey, path, idem, payload)
		if err != nil {
			return err
		}
		id, err := responseDataID(response)
		if err != nil {
			return err
		}
		fmt.Println("uploaded " + path + ": " + id)
	}
	return nil
}

func createReleaseArtifactManifest(args []string) error {
	fs := flag.NewFlagSet("release manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "evydence-release-manifest.json", "output manifest path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	files := fs.Args()
	if len(files) == 0 {
		return usage()
	}
	artifacts := []map[string]any{}
	for _, path := range files {
		cleaned, err := cleanOperatorPath(path)
		if err != nil {
			return err
		}
		info, err := os.Stat(cleaned)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return errors.New("release artifact path must be a file")
		}
		digest, err := hashFile(cleaned)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, map[string]any{"path": filepath.Base(cleaned), "size": info.Size(), "digest": digest})
	}
	manifest := map[string]any{"schema_version": "evydence-release-artifacts.v1.0.0", "generated_at": time.Now().UTC().Format(time.RFC3339), "artifacts": artifacts}
	return writeJSONFile(*out, manifest)
}

func generateReleaseSigningKey(args []string) error {
	fs := flag.NewFlagSet("release keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privateOut := fs.String("private-out", "evydence-release-private.key", "private key output path")
	publicOut := fs.String("public-out", "evydence-release-public.key", "public key output path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(*privateOut), []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(*publicOut), []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		return err
	}
	fmt.Println("release signing keypair generated")
	return nil
}

func signReleaseArtifactManifest(args []string) error {
	fs := flag.NewFlagSet("release sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "release manifest path")
	privateKeyPath := fs.String("private-key", "", "base64 Ed25519 private key file")
	out := fs.String("out", "evydence-release-manifest.sig.json", "signature output path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*privateKeyPath) == "" {
		return usage()
	}
	canonical, hash, err := canonicalFileHash(*manifestPath)
	if err != nil {
		return err
	}
	priv, err := readBase64File(*privateKeyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), canonical)
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	signature := map[string]any{"schema_version": "evydence-release-signature.v1.0.0", "manifest_hash": hash, "algorithm": "Ed25519", "public_key": base64.StdEncoding.EncodeToString(pub), "signature": base64.StdEncoding.EncodeToString(sig)}
	return writeJSONFile(*out, signature)
}

func verifyReleaseArtifactManifest(args []string) error {
	fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "release manifest path")
	signaturePath := fs.String("signature", "", "release signature path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*signaturePath) == "" {
		return usage()
	}
	canonical, hash, err := canonicalFileHash(*manifestPath)
	if err != nil {
		return err
	}
	var signature struct {
		ManifestHash string `json:"manifest_hash"`
		Algorithm    string `json:"algorithm"`
		PublicKey    string `json:"public_key"`
		Signature    string `json:"signature"`
	}
	body, err := readFileStrict(*signaturePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, &signature); err != nil {
		return errors.New("release signature is not valid JSON")
	}
	pub, err := base64.StdEncoding.DecodeString(signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || signature.Algorithm != "Ed25519" {
		return errors.New("invalid release signature metadata")
	}
	value, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(value) != ed25519.SignatureSize {
		return errors.New("invalid release signature value")
	}
	if signature.ManifestHash != hash || !ed25519.Verify(ed25519.PublicKey(pub), canonical, value) {
		return errors.New("release manifest signature verification failed")
	}
	if err := verifyReleaseArtifactFiles(*manifestPath, body); err != nil {
		return err
	}
	fmt.Println("release manifest verified")
	return nil
}

func postEvydence(ctx context.Context, client *http.Client, apiURL, apiKey, path, idem string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return postRawEvydence(ctx, client, apiURL, apiKey, path, idem, body)
}

func writeJSONFile(path string, value any) error {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.WriteFile(cleaned, body, 0o600); err != nil {
		return err
	}
	fmt.Println("wrote " + cleaned)
	return nil
}

func readFileStrict(path string) ([]byte, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return nil, err
	}
	// #nosec G304,G703 -- this CLI intentionally reads a local operator-specified file.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func readBase64File(path string, size int) ([]byte, error) {
	body, err := readFileStrict(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 key file")
	}
	return decoded, nil
}

func canonicalFileHash(path string) ([]byte, string, error) {
	body, err := readFileStrict(path)
	if err != nil {
		return nil, "", err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return nil, "", errors.New("manifest is not valid JSON")
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalJSONHash(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return "", err
	}
	body, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return hashBytes(body), nil
}

func hashBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashString(value string) string {
	return hashBytes([]byte(value))
}

func decodeBase64Flexible(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func verifyReleaseArtifactFiles(manifestPath string, _ []byte) error {
	body, err := readFileStrict(manifestPath)
	if err != nil {
		return err
	}
	var manifest struct {
		Artifacts []struct {
			Path   string `json:"path"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return errors.New("release manifest is not valid JSON")
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("release manifest has no artifacts")
	}
	baseDir := filepath.Dir(filepath.Clean(manifestPath))
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(baseDir, artifact.Path)
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		if digest != artifact.Digest {
			return fmt.Errorf("artifact digest mismatch for %s", artifact.Path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Size() != artifact.Size {
			return fmt.Errorf("artifact size mismatch for %s", artifact.Path)
		}
	}
	return nil
}

func postRawEvydence(ctx context.Context, client *http.Client, apiURL, apiKey, path, idem string, body []byte) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	baseURL, err := cleanAPIURL(apiURL)
	if err != nil {
		return nil, err
	}
	// #nosec G704 -- this CLI intentionally sends requests to an operator-specified Evydence API URL after scheme and host validation.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Idempotency-Key", idem)
	req.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- request target is the validated operator-specified Evydence API URL for this CLI command.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, safeAPIError(resp.StatusCode, responseBody)
	}
	return responseBody, nil
}

func cleanAPIURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid Evydence API URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("evydence API URL must use http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("evydence API URL host is required")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func safeAPIError(status int, body []byte) error {
	var problem struct {
		Detail string `json:"detail"`
		Code   string `json:"code"`
		Ext    struct {
			Code string `json:"code"`
		} `json:"-"`
	}
	_ = json.Unmarshal(body, &problem)
	code := problem.Code
	if code == "" {
		code = problem.Ext.Code
	}
	detail := strings.TrimSpace(problem.Detail)
	if detail == "" {
		detail = http.StatusText(status)
	}
	if code != "" {
		return fmt.Errorf("evydence API request failed: status=%d code=%s detail=%s", status, code, detail)
	}
	return fmt.Errorf("evydence API request failed: status=%d detail=%s", status, detail)
}

func responseDataID(body []byte) (string, error) {
	var decoded struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.Data.ID == "" {
		return "", errors.New("evydence API response missing data.id")
	}
	return decoded.Data.ID, nil
}

func envRequired(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func atoiDefault(value string, fallback int) int {
	var out int
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &out); err != nil || out <= 0 {
		return fallback
	}
	return out
}
