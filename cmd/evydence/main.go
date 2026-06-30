package main

import (
	"archive/zip"
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
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
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
	case "package":
		if len(args) < 2 || args[1] != "verify" {
			return usage()
		}
		return verifyCustomerPackage(args[2:])
	case "github-actions":
		if len(args) < 2 || args[1] != "upload-build" {
			return usage()
		}
		return uploadGitHubActionsBuild(context.Background(), http.DefaultClient, args[2:])
	case "ci":
		if len(args) < 2 || args[1] != "preflight" {
			return usage()
		}
		return ciPreflight(context.Background(), http.DefaultClient, args[2:])
	case "import-bundle":
		if len(args) < 2 || args[1] != "upload" {
			return usage()
		}
		return uploadEvidenceBundleImport(context.Background(), http.DefaultClient, args[2:])
	case "upload":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "manifest":
			return uploadManifestRequests(context.Background(), http.DefaultClient, args[2:])
		case "validate-manifest":
			return validateUploadManifestCommand(args[2:])
		default:
			return usage()
		}
	case "release":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "upload-evidence":
			return uploadReleaseEvidence(context.Background(), http.DefaultClient, args[2:])
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
	return errors.New("usage: evydence hash <file> | evydence verify-manifest <manifest.json> --hash sha256:<hex> | evydence verify-evidence-bundle <bundle.json> | evydence verify-audit-chain <chain.json> | evydence package verify ... | evydence github-actions upload-build ... | evydence ci preflight ... | evydence import-bundle upload ... | evydence upload manifest|validate-manifest ... | evydence release upload-evidence|manifest|sign|verify|keygen")
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
	bundle, err := readEvidenceBundle(path)
	if err != nil {
		return err
	}
	verified, err := verifyEvidenceBundleStruct(bundle)
	if err != nil {
		return err
	}
	if verified.Signed {
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

type offlineEvidenceBundle struct {
	Manifest      map[string]any      `json:"manifest"`
	ManifestHash  string              `json:"manifest_hash"`
	SignatureRefs []string            `json:"signature_refs"`
	Signatures    []offlineSignature  `json:"signatures"`
	SigningKeys   []offlineSigningKey `json:"signing_keys"`
}

type offlineEvidenceBundleVerification struct {
	ManifestHash  string
	Signed        bool
	SigningKeyIDs []string
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

func readEvidenceBundle(path string) (offlineEvidenceBundle, error) {
	body, err := readFileStrict(path)
	if err != nil {
		return offlineEvidenceBundle{}, err
	}
	var bundle offlineEvidenceBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return offlineEvidenceBundle{}, errors.New("evidence bundle is not JSON")
	}
	return bundle, nil
}

func verifyEvidenceBundleStruct(bundle offlineEvidenceBundle) (offlineEvidenceBundleVerification, error) {
	if len(bundle.Manifest) == 0 || strings.TrimSpace(bundle.ManifestHash) == "" {
		return offlineEvidenceBundleVerification{}, errors.New("evidence bundle missing manifest or manifest_hash")
	}
	canonical, err := json.Marshal(bundle.Manifest)
	if err != nil {
		return offlineEvidenceBundleVerification{}, err
	}
	var normalized any
	if err := json.Unmarshal(canonical, &normalized); err != nil {
		return offlineEvidenceBundleVerification{}, err
	}
	canonical, err = json.Marshal(normalized)
	if err != nil {
		return offlineEvidenceBundleVerification{}, err
	}
	sum := sha256.Sum256(canonical)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != bundle.ManifestHash {
		return offlineEvidenceBundleVerification{}, fmt.Errorf("evidence bundle hash mismatch: got %s want %s", got, bundle.ManifestHash)
	}
	keyIDs := evidenceBundleSigningKeyIDs(bundle)
	if err := verifyOfflineSignatures(bundle.ManifestHash, bundle.SignatureRefs, bundle.Signatures, bundle.SigningKeys); err != nil {
		return offlineEvidenceBundleVerification{}, err
	}
	return offlineEvidenceBundleVerification{ManifestHash: bundle.ManifestHash, Signed: len(bundle.Signatures) > 0 || len(bundle.SigningKeys) > 0, SigningKeyIDs: keyIDs}, nil
}

func evidenceBundleSigningKeyIDs(bundle offlineEvidenceBundle) []string {
	byID := map[string]offlineSignature{}
	for _, signature := range bundle.Signatures {
		if strings.TrimSpace(signature.ID) != "" {
			byID[signature.ID] = signature
		}
	}
	seen := map[string]bool{}
	keyIDs := []string{}
	for _, ref := range bundle.SignatureRefs {
		signature, ok := byID[strings.TrimSpace(ref)]
		if !ok || strings.TrimSpace(signature.KeyID) == "" || seen[signature.KeyID] {
			continue
		}
		seen[signature.KeyID] = true
		keyIDs = append(keyIDs, signature.KeyID)
	}
	return keyIDs
}

const (
	customerPackageSchemaVersion = "customer-security-package.v2.0.0"
	maxCustomerPackageFileBytes  = int64(10 << 20)
)

type customerPackageVerifyResult struct {
	ManifestHash        string
	PackageID           string
	TenantID            string
	ProductID           string
	ReleaseID           string
	EvidenceIDs         []string
	ReleaseBundleHashes []string
}

type customerPackageArchiveFiles struct {
	Manifest       []byte
	DecisionExport []byte
	Metadata       map[string]any
	Verification   map[string]any
}

const customerDecisionExportSchemaVersion = "customer-vulnerability-decisions.v1.0.0"

func verifyCustomerPackage(args []string) error {
	fs := flag.NewFlagSet("package verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "customer package manifest JSON path")
	archivePath := fs.String("archive", "", "customer package ZIP path")
	bundlePath := fs.String("bundle", "", "evidence bundle JSON path")
	expectedHash := fs.String("hash", "", "expected canonical manifest hash sha256:<hex>")
	expectedTenantID := fs.String("expected-tenant-id", "", "expected tenant id")
	expectedProductID := fs.String("expected-product-id", "", "expected product id")
	expectedReleaseID := fs.String("expected-release-id", "", "expected release id")
	expectedPackageID := fs.String("expected-package-id", "", "expected package id")
	expectedSigningKeyID := fs.String("expected-signing-key-id", "", "expected evidence-bundle signing key id")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if fs.NArg() != 0 || (strings.TrimSpace(*manifestPath) == "" && strings.TrimSpace(*archivePath) == "") {
		return usage()
	}

	var archive customerPackageArchiveFiles
	var manifestBody []byte
	if strings.TrimSpace(*archivePath) != "" {
		var err error
		archive, err = readCustomerPackageArchive(*archivePath)
		if err != nil {
			return err
		}
		manifestBody = archive.Manifest
	}
	if strings.TrimSpace(*manifestPath) != "" {
		body, err := readFileStrict(*manifestPath)
		if err != nil {
			return err
		}
		if len(manifestBody) > 0 {
			archiveHash, err := canonicalJSONBytesHash(manifestBody)
			if err != nil {
				return err
			}
			fileHash, err := canonicalJSONBytesHash(body)
			if err != nil {
				return err
			}
			if archiveHash != fileHash {
				return errors.New("manifest file and archive manifest do not match")
			}
		}
		manifestBody = body
	}

	result, err := verifyCustomerPackageManifestBytes(manifestBody)
	if err != nil {
		return err
	}
	if expected := strings.TrimSpace(*expectedHash); expected != "" && result.ManifestHash != expected {
		return fmt.Errorf("customer package manifest hash mismatch: got %s want %s", result.ManifestHash, expected)
	}
	if err := verifyExpectedValue("tenant id", result.TenantID, *expectedTenantID); err != nil {
		return err
	}
	if err := verifyExpectedValue("product id", result.ProductID, *expectedProductID); err != nil {
		return err
	}
	if err := verifyExpectedValue("release id", result.ReleaseID, *expectedReleaseID); err != nil {
		return err
	}
	if err := verifyExpectedValue("package id", result.PackageID, *expectedPackageID); err != nil {
		return err
	}
	if len(archive.Manifest) > 0 {
		if err := verifyCustomerPackageArchiveMetadata(archive, result); err != nil {
			return err
		}
	}
	bundleStatus := "not supplied"
	if strings.TrimSpace(*bundlePath) != "" {
		bundle, err := readEvidenceBundle(*bundlePath)
		if err != nil {
			return err
		}
		verified, err := verifyEvidenceBundleStruct(bundle)
		if err != nil {
			return err
		}
		if expected := strings.TrimSpace(*expectedSigningKeyID); expected != "" && !stringInSlice(verified.SigningKeyIDs, expected) {
			return fmt.Errorf("expected signing key id %s was not used by evidence bundle signatures", expected)
		}
		if err := verifyCustomerPackageEvidenceCoverage(result.EvidenceIDs, bundle.Manifest); err != nil {
			return err
		}
		bundleStatus = "verified"
		if verified.Signed {
			bundleStatus = "verified with signature"
		}
	}
	fmt.Printf("customer package verified\npackage_id: %s\nproduct_id: %s\nrelease_id: %s\nmanifest_hash: %s\nevidence_bundle: %s\n", result.PackageID, result.ProductID, result.ReleaseID, result.ManifestHash, bundleStatus)
	return nil
}

func verifyCustomerPackageManifestBytes(body []byte) (customerPackageVerifyResult, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return customerPackageVerifyResult{}, errors.New("customer package manifest is empty")
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return customerPackageVerifyResult{}, errors.New("customer package manifest is not valid JSON")
	}
	if err := rejectCustomerPackageSensitiveKeys(raw); err != nil {
		return customerPackageVerifyResult{}, err
	}
	hash, err := canonicalJSONBytesHash(body)
	if err != nil {
		return customerPackageVerifyResult{}, err
	}
	var manifest struct {
		SchemaVersion    string              `json:"schema_version"`
		PackageVersion   string              `json:"package_version"`
		PackageID        string              `json:"package_id"`
		ID               string              `json:"id"`
		Title            string              `json:"title"`
		GeneratedAt      string              `json:"generated_at"`
		Tenant           struct{ ID string } `json:"tenant"`
		ProductID        string              `json:"product_id"`
		Product          struct{ ID string } `json:"product"`
		ReleaseID        string              `json:"release_id"`
		Release          struct{ ID string } `json:"release"`
		RedactionProfile struct {
			ID            string   `json:"id"`
			Name          string   `json:"name"`
			AllowedTypes  []string `json:"allowed_types"`
			SchemaVersion string   `json:"schema_version"`
		} `json:"redaction_profile"`
		EvidenceIDs     []string `json:"evidence_ids"`
		ArtifactDigests []struct {
			ID     string `json:"id"`
			Digest string `json:"digest"`
		} `json:"artifact_digests"`
		ReadinessSummary     map[string]any `json:"readiness_summary"`
		VerificationMaterial struct {
			HashAlgorithm  string `json:"hash_algorithm"`
			ReleaseBundles []struct {
				ManifestHash string `json:"manifest_hash"`
			} `json:"release_bundles"`
		} `json:"verification_material"`
		Limitations []string `json:"limitations"`
		NonClaims   []string `json:"non_claims"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return customerPackageVerifyResult{}, errors.New("customer package manifest structure is invalid")
	}
	if strings.TrimSpace(manifest.SchemaVersion) != customerPackageSchemaVersion || strings.TrimSpace(manifest.PackageVersion) != customerPackageSchemaVersion {
		return customerPackageVerifyResult{}, errors.New("customer package manifest schema_version is unsupported")
	}
	packageID := strings.TrimSpace(manifest.PackageID)
	if packageID == "" {
		packageID = strings.TrimSpace(manifest.ID)
	}
	if packageID == "" || strings.TrimSpace(manifest.ID) == "" || packageID != strings.TrimSpace(manifest.ID) {
		return customerPackageVerifyResult{}, errors.New("customer package manifest id/package_id mismatch")
	}
	if strings.TrimSpace(manifest.Title) == "" || strings.TrimSpace(manifest.Tenant.ID) == "" || strings.TrimSpace(manifest.ProductID) == "" || strings.TrimSpace(manifest.Product.ID) == "" {
		return customerPackageVerifyResult{}, errors.New("customer package manifest missing required identity fields")
	}
	if strings.TrimSpace(manifest.ProductID) != strings.TrimSpace(manifest.Product.ID) {
		return customerPackageVerifyResult{}, errors.New("customer package manifest product id mismatch")
	}
	if strings.TrimSpace(manifest.ReleaseID) != "" && strings.TrimSpace(manifest.Release.ID) != "" && strings.TrimSpace(manifest.ReleaseID) != strings.TrimSpace(manifest.Release.ID) {
		return customerPackageVerifyResult{}, errors.New("customer package manifest release id mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(manifest.GeneratedAt)); err != nil {
		return customerPackageVerifyResult{}, errors.New("customer package manifest generated_at must be RFC3339")
	}
	if strings.TrimSpace(manifest.RedactionProfile.ID) == "" || strings.TrimSpace(manifest.RedactionProfile.Name) == "" || len(manifest.RedactionProfile.AllowedTypes) == 0 || strings.TrimSpace(manifest.RedactionProfile.SchemaVersion) == "" {
		return customerPackageVerifyResult{}, errors.New("customer package manifest missing redaction profile details")
	}
	if len(manifest.ReadinessSummary) == 0 || len(manifest.Limitations) == 0 || len(manifest.NonClaims) == 0 {
		return customerPackageVerifyResult{}, errors.New("customer package manifest missing readiness, limitations, or non-claims")
	}
	if algorithm := strings.TrimSpace(manifest.VerificationMaterial.HashAlgorithm); algorithm != "" && algorithm != "sha256" {
		return customerPackageVerifyResult{}, errors.New("customer package manifest uses unsupported hash algorithm")
	}
	for _, artifact := range manifest.ArtifactDigests {
		if strings.TrimSpace(artifact.ID) == "" || !validSHA256Digest(artifact.Digest) {
			return customerPackageVerifyResult{}, errors.New("customer package manifest has invalid artifact digest")
		}
	}
	releaseBundleHashes := []string{}
	for _, bundle := range manifest.VerificationMaterial.ReleaseBundles {
		if strings.TrimSpace(bundle.ManifestHash) != "" {
			releaseBundleHashes = append(releaseBundleHashes, strings.TrimSpace(bundle.ManifestHash))
		}
	}
	return customerPackageVerifyResult{
		ManifestHash:        hash,
		PackageID:           packageID,
		TenantID:            strings.TrimSpace(manifest.Tenant.ID),
		ProductID:           strings.TrimSpace(manifest.ProductID),
		ReleaseID:           strings.TrimSpace(manifest.ReleaseID),
		EvidenceIDs:         trimStringSlice(manifest.EvidenceIDs),
		ReleaseBundleHashes: releaseBundleHashes,
	}, nil
}

func readCustomerPackageArchive(path string) (customerPackageArchiveFiles, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return customerPackageArchiveFiles{}, err
	}
	// #nosec G304 -- this CLI intentionally reads a local operator-specified ZIP archive and never extracts entries to disk.
	reader, err := zip.OpenReader(cleaned)
	if err != nil {
		return customerPackageArchiveFiles{}, err
	}
	defer func() {
		_ = reader.Close()
	}()
	files := customerPackageArchiveFiles{}
	seenEntries := map[string]bool{}
	for _, file := range reader.File {
		if err := validateCustomerPackageArchiveEntryName(file.Name); err != nil {
			return customerPackageArchiveFiles{}, err
		}
		if seenEntries[file.Name] {
			return customerPackageArchiveFiles{}, fmt.Errorf("customer package archive duplicate archive entry %s", file.Name)
		}
		seenEntries[file.Name] = true
		switch file.Name {
		case "manifest.json":
			files.Manifest, err = readZIPFileLimited(file)
		case "package.json":
			var body []byte
			body, err = readZIPFileLimited(file)
			if err == nil {
				err = json.Unmarshal(body, &files.Metadata)
			}
		case "verification.json":
			var body []byte
			body, err = readZIPFileLimited(file)
			if err == nil {
				err = json.Unmarshal(body, &files.Verification)
			}
		case "vulnerability-decisions.json":
			files.DecisionExport, err = readZIPFileLimited(file)
		}
		if err != nil {
			return customerPackageArchiveFiles{}, err
		}
	}
	if len(files.Manifest) == 0 || len(files.Metadata) == 0 || len(files.Verification) == 0 {
		return customerPackageArchiveFiles{}, errors.New("customer package archive missing manifest.json, package.json, or verification.json")
	}
	return files, nil
}

func validateCustomerPackageArchiveEntryName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("customer package archive contains unsafe archive entry")
	}
	if strings.TrimSpace(name) != name || strings.Contains(name, "\x00") || strings.Contains(name, "\\") {
		return fmt.Errorf("customer package archive contains unsafe archive entry %s", name)
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("customer package archive contains unsafe archive entry %q", name)
		}
	}
	if pathpkg.IsAbs(name) || pathpkg.Clean(name) != name || strings.Contains(name, "/") {
		return fmt.Errorf("customer package archive contains unsafe archive entry %s", name)
	}
	return nil
}

func readZIPFileLimited(file *zip.File) ([]byte, error) {
	if file.UncompressedSize64 > uint64(maxCustomerPackageFileBytes) {
		return nil, fmt.Errorf("customer package archive entry %s is too large", file.Name)
	}
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rc.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(rc, maxCustomerPackageFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxCustomerPackageFileBytes {
		return nil, fmt.Errorf("customer package archive entry %s is too large", file.Name)
	}
	return body, nil
}

func verifyCustomerPackageArchiveMetadata(archive customerPackageArchiveFiles, result customerPackageVerifyResult) error {
	for name, document := range map[string]map[string]any{"package.json": archive.Metadata, "verification.json": archive.Verification} {
		if got := stringMapField(document, "manifest_hash"); got != result.ManifestHash {
			return fmt.Errorf("%s manifest_hash mismatch", name)
		}
		if got := stringMapField(document, "package_id"); got != "" && got != result.PackageID {
			return fmt.Errorf("%s package_id mismatch", name)
		}
		if name == "package.json" {
			if got := stringMapField(document, "id"); got != "" && got != result.PackageID {
				return fmt.Errorf("%s id mismatch", name)
			}
		}
	}
	if exportFile := stringMapField(archive.Verification, "decision_export_file"); strings.TrimSpace(exportFile) != "" {
		if strings.TrimSpace(exportFile) != "vulnerability-decisions.json" {
			return errors.New("verification.json decision_export_file is unsupported")
		}
		if len(archive.DecisionExport) == 0 {
			return errors.New("customer package archive missing declared vulnerability decision export")
		}
		if err := verifyCustomerDecisionExportBytes(archive.DecisionExport, result); err != nil {
			return err
		}
	}
	return nil
}

func verifyCustomerDecisionExportBytes(body []byte, result customerPackageVerifyResult) error {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("customer package decision export is not valid JSON")
	}
	if err := rejectCustomerPackageSensitiveKeys(raw); err != nil {
		return err
	}
	var export struct {
		SchemaVersion      string           `json:"schema_version"`
		PackageID          string           `json:"package_id"`
		ProductID          string           `json:"product_id"`
		ReleaseID          string           `json:"release_id"`
		SourceManifestHash string           `json:"source_manifest_hash"`
		Decisions          []map[string]any `json:"decisions"`
		Assumptions        []string         `json:"assumptions"`
		Limitations        []string         `json:"limitations"`
		GeneratedAt        string           `json:"generated_at"`
	}
	if err := json.Unmarshal(body, &export); err != nil {
		return errors.New("customer package decision export structure is invalid")
	}
	if strings.TrimSpace(export.SchemaVersion) != customerDecisionExportSchemaVersion {
		return errors.New("customer package decision export schema_version is unsupported")
	}
	if strings.TrimSpace(export.PackageID) != result.PackageID || strings.TrimSpace(export.ProductID) != result.ProductID || strings.TrimSpace(export.ReleaseID) != result.ReleaseID {
		return errors.New("customer package decision export scope mismatch")
	}
	if strings.TrimSpace(export.SourceManifestHash) != result.ManifestHash {
		return errors.New("customer package decision export manifest_hash mismatch")
	}
	if len(export.Decisions) == 0 || len(export.Assumptions) == 0 || len(export.Limitations) == 0 {
		return errors.New("customer package decision export missing decisions, assumptions, or limitations")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(export.GeneratedAt)); err != nil {
		return errors.New("customer package decision export generated_at must be RFC3339")
	}
	for _, decision := range export.Decisions {
		for _, key := range []string{"id", "vulnerability", "status", "impact_statement"} {
			if strings.TrimSpace(stringMapField(decision, key)) == "" {
				return fmt.Errorf("customer package decision export missing decision field %s", key)
			}
		}
	}
	return nil
}

func verifyCustomerPackageEvidenceCoverage(packageEvidenceIDs []string, bundleManifest map[string]any) error {
	if len(packageEvidenceIDs) == 0 {
		return nil
	}
	bundleIDs := stringSliceFromAny(bundleManifest["evidence_ids"])
	if len(bundleIDs) == 0 {
		return nil
	}
	for _, id := range packageEvidenceIDs {
		if !stringInSlice(bundleIDs, id) {
			return fmt.Errorf("evidence bundle does not include package evidence id %s", id)
		}
	}
	return nil
}

func canonicalJSONBytesHash(body []byte) (string, error) {
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return "", errors.New("manifest is not valid JSON")
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return hashBytes(canonical), nil
}

func validSHA256Digest(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func verifyExpectedValue(label, got, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	if strings.TrimSpace(got) != expected {
		return fmt.Errorf("customer package %s mismatch: got %s want %s", label, got, expected)
	}
	return nil
}

func rejectCustomerPackageSensitiveKeys(value any) error {
	return rejectCustomerPackageSensitiveKeysAt(value, "")
}

func rejectCustomerPackageSensitiveKeysAt(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(strings.TrimSpace(key))
			if prohibitedCustomerPackageManifestKey(lower) {
				if path == "" {
					return fmt.Errorf("customer package manifest contains prohibited field %s", key)
				}
				return fmt.Errorf("customer package manifest contains prohibited field %s.%s", path, key)
			}
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if err := rejectCustomerPackageSensitiveKeysAt(child, childPath); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectCustomerPackageSensitiveKeysAt(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func prohibitedCustomerPackageManifestKey(key string) bool {
	switch key {
	case "payload", "payload_bytes", "payload_ref", "object_key", "private_key", "token", "secret", "api_key_hash", "session_token_hash", "internal_notes":
		return true
	default:
		return false
	}
}

func stringMapField(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func stringSliceFromAny(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if ok && strings.TrimSpace(text) != "" {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}

func trimStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func stringInSlice(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
	manifest, err := readAndValidateUploadManifest(*manifestPath)
	if err != nil {
		return err
	}
	for _, req := range manifest.Requests {
		payload, err := req.PayloadBytes()
		if err != nil {
			return err
		}
		response, err := postRawEvydence(ctx, client, *apiURL, *apiKey, req.Path, req.IdempotencyKey, payload)
		if err != nil {
			return err
		}
		id, err := responseDataID(response)
		if err != nil {
			return err
		}
		fmt.Println("uploaded " + req.Path + ": " + id)
	}
	return nil
}

func validateUploadManifestCommand(args []string) error {
	fs := flag.NewFlagSet("upload validate-manifest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "upload manifest JSON path")
	if err := fs.Parse(args); err != nil {
		return usage()
	}
	if strings.TrimSpace(*manifestPath) == "" || fs.NArg() != 0 {
		return usage()
	}
	manifest, err := readAndValidateUploadManifest(*manifestPath)
	if err != nil {
		return err
	}
	fmt.Printf("upload manifest valid: %d requests\n", len(manifest.Requests))
	return nil
}

const (
	exitCIPreflightMissingConfig   = 2
	exitCIPreflightAuthFailure     = 3
	exitCIPreflightWrongScope      = 4
	exitCIPreflightWrongTenant     = 5
	exitCIPreflightInvalidManifest = 6
)

type cliExitError struct {
	code    int
	message string
}

func (e cliExitError) Error() string {
	return e.message
}

func (e cliExitError) ExitCode() int {
	return e.code
}

func ciPreflight(ctx context.Context, client *http.Client, args []string) error {
	fs := flag.NewFlagSet("ci preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apiURL := fs.String("url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
	apiKey := fs.String("api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
	productID := fs.String("product-id", strings.TrimSpace(os.Getenv("EVYDENCE_PRODUCT_ID")), "Evydence product ID")
	projectID := fs.String("project-id", strings.TrimSpace(os.Getenv("EVYDENCE_PROJECT_ID")), "Evydence project ID")
	releaseID := fs.String("release-id", strings.TrimSpace(os.Getenv("EVYDENCE_RELEASE_ID")), "Evydence release ID")
	artifactID := fs.String("artifact-id", strings.TrimSpace(os.Getenv("EVYDENCE_ARTIFACT_ID")), "Evydence artifact ID")
	manifestPath := fs.String("manifest", "", "upload manifest JSON path")
	if err := fs.Parse(args); err != nil {
		return ciExit(exitCIPreflightMissingConfig, "ci preflight configuration is invalid")
	}
	if fs.NArg() != 0 || strings.TrimSpace(*apiURL) == "" || strings.TrimSpace(*apiKey) == "" ||
		strings.TrimSpace(*productID) == "" || strings.TrimSpace(*projectID) == "" ||
		strings.TrimSpace(*releaseID) == "" || strings.TrimSpace(*artifactID) == "" ||
		strings.TrimSpace(*manifestPath) == "" {
		return ciExit(exitCIPreflightMissingConfig, "ci preflight requires url, api key, product id, project id, release id, artifact id, and manifest path")
	}
	manifest, err := readAndValidateUploadManifest(*manifestPath)
	if err != nil {
		return ciExit(exitCIPreflightInvalidManifest, "ci preflight manifest is invalid: "+err.Error())
	}
	if err := validatePreflightManifestIDs(manifest, *productID, *projectID, *releaseID, *artifactID); err != nil {
		return ciExit(exitCIPreflightInvalidManifest, err.Error())
	}
	productBody, err := getEvydence(ctx, client, *apiURL, *apiKey, "/v1/products/"+url.PathEscape(strings.TrimSpace(*productID)))
	if err != nil {
		return mapCIPreflightAPIError(err)
	}
	if err := ensureResponseDataID(productBody, *productID, "product"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	projectBody, err := getEvydence(ctx, client, *apiURL, *apiKey, "/v1/projects/"+url.PathEscape(strings.TrimSpace(*projectID)))
	if err != nil {
		return mapCIPreflightAPIError(err)
	}
	if err := ensureResponseDataID(projectBody, *projectID, "project"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	if err := ensureResponseDataField(projectBody, "product_id", *productID, "project product"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	releaseBody, err := getEvydence(ctx, client, *apiURL, *apiKey, "/v1/releases/"+url.PathEscape(strings.TrimSpace(*releaseID)))
	if err != nil {
		return mapCIPreflightAPIError(err)
	}
	if err := ensureResponseDataID(releaseBody, *releaseID, "release"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	if err := ensureResponseDataField(releaseBody, "product_id", *productID, "release product"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	artifactBody, err := getEvydence(ctx, client, *apiURL, *apiKey, "/v1/artifacts/"+url.PathEscape(strings.TrimSpace(*artifactID)))
	if err != nil {
		return mapCIPreflightAPIError(err)
	}
	if err := ensureResponseDataID(artifactBody, *artifactID, "artifact"); err != nil {
		return ciExit(exitCIPreflightWrongTenant, err.Error())
	}
	fmt.Printf("ci preflight ok: product=%s project=%s release=%s artifact=%s manifest_requests=%d\n", strings.TrimSpace(*productID), strings.TrimSpace(*projectID), strings.TrimSpace(*releaseID), strings.TrimSpace(*artifactID), len(manifest.Requests))
	return nil
}

func ciExit(code int, message string) error {
	return cliExitError{code: code, message: message}
}

func mapCIPreflightAPIError(err error) error {
	var apiErr apiRequestError
	if errors.As(err, &apiErr) {
		switch apiErr.status {
		case http.StatusUnauthorized:
			return ciExit(exitCIPreflightAuthFailure, "ci preflight authentication failed")
		case http.StatusForbidden:
			return ciExit(exitCIPreflightWrongScope, "ci preflight API key lacks required scope")
		case http.StatusNotFound:
			return ciExit(exitCIPreflightWrongTenant, "ci preflight resource was not found for this tenant")
		}
	}
	return err
}

func ensureResponseDataID(body []byte, expected, name string) error {
	return ensureResponseDataField(body, "id", expected, name)
}

func ensureResponseDataField(body []byte, field, expected, name string) error {
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return errors.New("ci preflight response is not valid JSON")
	}
	got, _ := decoded.Data[field].(string)
	if strings.TrimSpace(got) != strings.TrimSpace(expected) {
		return fmt.Errorf("ci preflight %s mismatch", name)
	}
	return nil
}

func validatePreflightManifestIDs(manifest uploadManifestFile, productID, projectID, releaseID, artifactID string) error {
	for index, req := range manifest.Requests {
		payload, err := req.PayloadBytes()
		if err != nil {
			return fmt.Errorf("ci preflight manifest request %d payload cannot be read", index)
		}
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			return fmt.Errorf("ci preflight manifest request %d payload is not valid JSON", index)
		}
		if err := checkManifestIDField(value, "product_id", productID, index); err != nil {
			return err
		}
		if err := checkManifestIDField(value, "project_id", projectID, index); err != nil {
			return err
		}
		if err := checkManifestIDField(value, "release_id", releaseID, index); err != nil {
			return err
		}
		if err := checkManifestIDField(value, "artifact_id", artifactID, index); err != nil {
			return err
		}
	}
	return nil
}

func checkManifestIDField(value any, field, expected string, index int) error {
	found := []string{}
	var walk func(any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == field {
					if got, ok := child.(string); ok && strings.TrimSpace(got) != "" {
						found = append(found, strings.TrimSpace(got))
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	for _, got := range found {
		if got != strings.TrimSpace(expected) {
			return fmt.Errorf("ci preflight manifest request %d %s does not match configured value", index, field)
		}
	}
	return nil
}

const uploadManifestSchemaVersion = "evydence-upload-manifest.v1.0.0"

type uploadManifestFile struct {
	SchemaVersion string                  `json:"schema_version"`
	Requests      []uploadManifestRequest `json:"requests"`
}

type uploadManifestRequest struct {
	Kind           string          `json:"kind"`
	Path           string          `json:"path"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
	PayloadFile    string          `json:"payload_file"`
	payloadPath    string
}

func readAndValidateUploadManifest(path string) (uploadManifestFile, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return uploadManifestFile{}, err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified upload manifest.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return uploadManifestFile{}, err
	}
	var manifest uploadManifestFile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return uploadManifestFile{}, errors.New("upload manifest is not valid JSON or contains unknown fields")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return uploadManifestFile{}, errors.New("upload manifest must contain one JSON document")
	}
	if manifest.SchemaVersion != "" && manifest.SchemaVersion != uploadManifestSchemaVersion {
		return uploadManifestFile{}, fmt.Errorf("upload manifest schema_version must be %s", uploadManifestSchemaVersion)
	}
	if len(manifest.Requests) == 0 || len(manifest.Requests) > 100 {
		return uploadManifestFile{}, errors.New("upload manifest must contain 1-100 requests")
	}
	baseDir := filepath.Dir(cleaned)
	for i := range manifest.Requests {
		if err := manifest.Requests[i].Validate(i, baseDir); err != nil {
			return uploadManifestFile{}, err
		}
	}
	return manifest, nil
}

func (r *uploadManifestRequest) Validate(index int, baseDir string) error {
	r.Kind = strings.TrimSpace(r.Kind)
	r.Path = strings.TrimSpace(r.Path)
	r.IdempotencyKey = strings.TrimSpace(r.IdempotencyKey)
	r.PayloadFile = strings.TrimSpace(r.PayloadFile)
	if !strings.HasPrefix(r.Path, "/v1/") || r.IdempotencyKey == "" {
		return fmt.Errorf("upload request %d missing /v1 path or idempotency key", index)
	}
	if r.Kind != "" && !uploadManifestKindAllowsPath(r.Kind, r.Path) {
		return fmt.Errorf("upload request %d kind %q does not allow path %q", index, r.Kind, r.Path)
	}
	hasInlinePayload := len(bytes.TrimSpace(r.Payload)) > 0
	hasPayloadFile := r.PayloadFile != ""
	if hasInlinePayload == hasPayloadFile {
		return fmt.Errorf("upload request %d must set exactly one of payload or payload_file", index)
	}
	if hasInlinePayload && !json.Valid(r.Payload) {
		return fmt.Errorf("upload request %d payload is not valid JSON", index)
	}
	if hasPayloadFile {
		payloadPath, err := cleanManifestPayloadPath(baseDir, r.PayloadFile)
		if err != nil {
			return fmt.Errorf("upload request %d: %w", index, err)
		}
		r.payloadPath = payloadPath
		// #nosec G304,G703 -- payload files are local operator-selected files constrained to the manifest directory.
		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			return fmt.Errorf("upload request %d payload_file cannot be read", index)
		}
		if len(bytes.TrimSpace(payload)) == 0 || !json.Valid(payload) {
			return fmt.Errorf("upload request %d payload_file is not valid JSON", index)
		}
	}
	return nil
}

func (r uploadManifestRequest) PayloadBytes() ([]byte, error) {
	if r.payloadPath == "" {
		return r.Payload, nil
	}
	// #nosec G304,G703 -- payload files were already validated and constrained to the manifest directory.
	return os.ReadFile(r.payloadPath)
}

func cleanManifestPayloadPath(baseDir, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", errors.New("payload_file is required")
	}
	if strings.Contains(rel, "\x00") {
		return "", errors.New("payload_file contains a NUL byte")
	}
	if filepath.IsAbs(rel) {
		return "", errors.New("payload_file must be relative to the manifest directory")
	}
	cleanRel := filepath.Clean(rel)
	if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return "", errors.New("payload_file must stay inside the manifest directory")
	}
	baseEval, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return "", errors.New("manifest directory cannot be resolved")
	}
	full := filepath.Join(baseEval, cleanRel)
	fullEval, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", errors.New("payload_file cannot be resolved")
	}
	relative, err := filepath.Rel(baseEval, fullEval)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("payload_file must stay inside the manifest directory")
	}
	return fullEval, nil
}

func uploadManifestKindAllowsPath(kind, path string) bool {
	switch strings.TrimSpace(kind) {
	case "artifact":
		return path == "/v1/artifacts"
	case "sbom":
		return path == "/v1/sboms" || path == "/v1/sboms/spdx"
	case "scan", "vulnerability_scan":
		return path == "/v1/vulnerability-scans"
	case "vex":
		return path == "/v1/vex" || path == "/v1/vex/cyclonedx"
	case "provenance", "build", "build_attestation":
		return path == "/v1/builds" || strings.HasPrefix(path, "/v1/builds/")
	case "approval":
		return path == "/v1/approvals" || strings.HasPrefix(path, "/v1/releases/")
	case "package_export", "customer_package":
		return path == "/v1/customer-packages"
	case "release_bundle":
		return path == "/v1/release-bundles"
	case "evidence":
		return path == "/v1/evidence"
	default:
		return false
	}
}

type releaseUploadConfig struct {
	APIURL            string
	APIKey            string
	ProductID         string
	ProductName       string
	ProductSlug       string
	CreateProduct     bool
	ReleaseID         string
	ReleaseVersion    string
	CreateRelease     bool
	ArtifactID        string
	ArtifactPath      string
	ArtifactName      string
	ArtifactMediaType string
	CreateArtifact    bool
	SBOMPath          string
	ScanPath          string
	ScanScanner       string
	TargetRef         string
	VEXPath           string
	CreateBundle      bool
	DryRun            bool
	IdempotencyPrefix string
}

func uploadReleaseEvidence(ctx context.Context, client *http.Client, args []string) error {
	cfg, err := parseReleaseUploadConfig(args)
	if err != nil {
		return err
	}
	artifact, err := releaseUploadArtifactMetadata(cfg.ArtifactPath, cfg.ArtifactName, cfg.ArtifactMediaType)
	if err != nil {
		return err
	}
	sbomPayload, err := readOptionalJSONPayload(cfg.SBOMPath, "SBOM")
	if err != nil {
		return err
	}
	scanPayload, err := readOptionalJSONPayload(cfg.ScanPath, "vulnerability scan")
	if err != nil {
		return err
	}
	vexPayload, err := readOptionalJSONPayload(cfg.VEXPath, "VEX")
	if err != nil {
		return err
	}
	if len(sbomPayload) == 0 && len(scanPayload) == 0 && len(vexPayload) == 0 && !cfg.CreateBundle {
		return errors.New("provide at least one evidence file or leave --create-bundle enabled")
	}
	if cfg.ArtifactPath != "" && cfg.ArtifactID == "" && !cfg.CreateArtifact {
		return errors.New("--artifact-id is required when --artifact is supplied unless --create-artifact is set")
	}
	if cfg.ReleaseID == "" && !cfg.CreateRelease {
		return errors.New("--release-id is required unless --create-release is set")
	}
	if cfg.ProductID == "" && (cfg.CreateRelease || cfg.CreateProduct) && !cfg.CreateProduct {
		return errors.New("--product-id is required unless --create-product is set")
	}
	if cfg.CreateProduct && (cfg.ProductName == "" || cfg.ProductSlug == "") {
		return errors.New("--product-name and --product-slug are required with --create-product")
	}
	if cfg.CreateRelease && cfg.ReleaseVersion == "" {
		return errors.New("--release-version is required with --create-release")
	}
	if cfg.CreateArtifact && cfg.ArtifactPath == "" {
		return errors.New("--artifact is required with --create-artifact")
	}
	if !cfg.DryRun && (cfg.APIURL == "" || cfg.APIKey == "") {
		return usage()
	}
	if cfg.IdempotencyPrefix == "" {
		cfg.IdempotencyPrefix = releaseUploadIdempotencyPrefix(cfg, artifact, sbomPayload, scanPayload, vexPayload)
	}
	productID := cfg.ProductID
	if cfg.CreateProduct {
		id, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/products", cfg.IdempotencyPrefix+"-product", map[string]any{
			"name": cfg.ProductName,
			"slug": cfg.ProductSlug,
		}, "<created-product-id>")
		if err != nil {
			return err
		}
		productID = id
	}
	releaseID := cfg.ReleaseID
	if cfg.CreateRelease {
		if productID == "" {
			return errors.New("product id is required before creating a release")
		}
		id, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/releases", cfg.IdempotencyPrefix+"-release", map[string]any{
			"product_id": productID,
			"version":    cfg.ReleaseVersion,
		}, "<created-release-id>")
		if err != nil {
			return err
		}
		releaseID = id
	}
	if releaseID == "" {
		return errors.New("release id is required")
	}
	artifactID := cfg.ArtifactID
	if cfg.CreateArtifact {
		id, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/artifacts", cfg.IdempotencyPrefix+"-artifact", map[string]any{
			"name":       artifact.Name,
			"media_type": artifact.MediaType,
			"digest":     artifact.Digest,
			"size":       artifact.Size,
		}, "<created-artifact-id>")
		if err != nil {
			return err
		}
		artifactID = id
	}
	if len(sbomPayload) > 0 {
		if _, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/sboms", cfg.IdempotencyPrefix+"-sbom", map[string]any{
			"release_id":  releaseID,
			"artifact_id": artifactID,
			"payload":     json.RawMessage(sbomPayload),
		}, "<created-sbom-id>"); err != nil {
			return err
		}
	}
	if len(scanPayload) > 0 {
		payload, err := buildReleaseUploadScanPayload(scanPayload, releaseID, cfg.TargetRef, cfg.ScanScanner, artifact)
		if err != nil {
			return err
		}
		if _, err := postReleaseUploadRaw(ctx, client, cfg, "/v1/vulnerability-scans", cfg.IdempotencyPrefix+"-scan", payload, "<created-scan-id>"); err != nil {
			return err
		}
	}
	if len(vexPayload) > 0 {
		if _, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/vex", cfg.IdempotencyPrefix+"-vex", map[string]any{
			"release_id":  releaseID,
			"artifact_id": artifactID,
			"payload":     json.RawMessage(vexPayload),
		}, "<created-vex-id>"); err != nil {
			return err
		}
	}
	if cfg.CreateBundle {
		if _, err := postReleaseUploadJSON(ctx, client, cfg, "/v1/release-bundles", cfg.IdempotencyPrefix+"-release-bundle", map[string]any{
			"release_id": releaseID,
		}, "<created-release-bundle-id>"); err != nil {
			return err
		}
	}
	printReleaseUploadNextSteps(cfg.APIURL, releaseID)
	return nil
}

func parseReleaseUploadConfig(args []string) (releaseUploadConfig, error) {
	fs := flag.NewFlagSet("release upload-evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := releaseUploadConfig{CreateBundle: true, ArtifactMediaType: "application/octet-stream", ScanScanner: "generic"}
	productAlias := ""
	releaseAlias := ""
	fs.StringVar(&cfg.APIURL, "url", strings.TrimSpace(os.Getenv("EVYDENCE_API_URL")), "Evydence API URL")
	fs.StringVar(&cfg.APIKey, "api-key", strings.TrimSpace(os.Getenv("EVYDENCE_API_KEY")), "Evydence API key")
	fs.StringVar(&cfg.ProductID, "product-id", "", "existing product id")
	fs.StringVar(&productAlias, "product", "", "existing product id alias")
	fs.StringVar(&cfg.ProductName, "product-name", "", "product name used with --create-product")
	fs.StringVar(&cfg.ProductSlug, "product-slug", "", "product slug used with --create-product")
	fs.BoolVar(&cfg.CreateProduct, "create-product", false, "create product before uploading evidence")
	fs.StringVar(&cfg.ReleaseID, "release-id", "", "existing release id")
	fs.StringVar(&releaseAlias, "release", "", "existing release id alias")
	fs.StringVar(&cfg.ReleaseVersion, "release-version", "", "release version used with --create-release")
	fs.BoolVar(&cfg.CreateRelease, "create-release", false, "create release before uploading evidence")
	fs.StringVar(&cfg.ArtifactID, "artifact-id", "", "existing artifact id")
	fs.StringVar(&cfg.ArtifactPath, "artifact", "", "artifact file path used for digest and optional registration")
	fs.StringVar(&cfg.ArtifactName, "artifact-name", "", "artifact name; defaults to artifact file basename")
	fs.StringVar(&cfg.ArtifactMediaType, "artifact-media-type", "application/octet-stream", "artifact media type used with --create-artifact")
	fs.BoolVar(&cfg.CreateArtifact, "create-artifact", false, "register artifact before uploading evidence")
	fs.StringVar(&cfg.SBOMPath, "sbom", "", "CycloneDX SBOM JSON path")
	fs.StringVar(&cfg.ScanPath, "scan", "", "Evydence generic vulnerability scan JSON path")
	fs.StringVar(&cfg.ScanScanner, "scan-scanner", "generic", "scanner name to use when the scan JSON omits scanner")
	fs.StringVar(&cfg.TargetRef, "target-ref", "", "scan target reference; defaults to artifact digest when available")
	fs.StringVar(&cfg.VEXPath, "vex", "", "OpenVEX JSON path")
	fs.BoolVar(&cfg.CreateBundle, "create-bundle", true, "create a release bundle after uploads")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "validate inputs and print planned requests without network calls")
	fs.StringVar(&cfg.IdempotencyPrefix, "idempotency-prefix", "", "stable idempotency prefix")
	if err := fs.Parse(args); err != nil {
		return releaseUploadConfig{}, usage()
	}
	if fs.NArg() != 0 {
		return releaseUploadConfig{}, usage()
	}
	cfg.APIURL = strings.TrimSpace(cfg.APIURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.ProductID = firstNonEmpty(cfg.ProductID, productAlias)
	cfg.ReleaseID = firstNonEmpty(cfg.ReleaseID, releaseAlias)
	cfg.ProductName = strings.TrimSpace(cfg.ProductName)
	cfg.ProductSlug = strings.TrimSpace(cfg.ProductSlug)
	cfg.ReleaseVersion = strings.TrimSpace(cfg.ReleaseVersion)
	cfg.ArtifactID = strings.TrimSpace(cfg.ArtifactID)
	cfg.ArtifactName = strings.TrimSpace(cfg.ArtifactName)
	cfg.ArtifactMediaType = firstNonEmpty(cfg.ArtifactMediaType, "application/octet-stream")
	cfg.ScanScanner = firstNonEmpty(cfg.ScanScanner, "generic")
	cfg.TargetRef = strings.TrimSpace(cfg.TargetRef)
	cfg.IdempotencyPrefix = strings.TrimSpace(cfg.IdempotencyPrefix)
	return cfg, nil
}

type releaseUploadArtifact struct {
	Name      string
	MediaType string
	Digest    string
	Size      int64
}

func releaseUploadArtifactMetadata(path, name, mediaType string) (releaseUploadArtifact, error) {
	if strings.TrimSpace(path) == "" {
		return releaseUploadArtifact{Name: strings.TrimSpace(name), MediaType: firstNonEmpty(mediaType, "application/octet-stream")}, nil
	}
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return releaseUploadArtifact{}, err
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return releaseUploadArtifact{}, err
	}
	if info.IsDir() {
		return releaseUploadArtifact{}, errors.New("--artifact must point to a file")
	}
	digest, err := hashFile(cleaned)
	if err != nil {
		return releaseUploadArtifact{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = filepath.Base(cleaned)
	}
	return releaseUploadArtifact{Name: strings.TrimSpace(name), MediaType: firstNonEmpty(mediaType, "application/octet-stream"), Digest: digest, Size: info.Size()}, nil
}

func readOptionalJSONPayload(path, label string) (json.RawMessage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	body, err := readFileStrict(path)
	if err != nil {
		return nil, err
	}
	if len(body) > 20<<20 {
		return nil, fmt.Errorf("%s payload exceeds 20 MiB", label)
	}
	var normalized any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("%s payload is not valid JSON", label)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%s payload must contain one JSON document", label)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func buildReleaseUploadScanPayload(raw json.RawMessage, releaseID, targetRef, scanner string, artifact releaseUploadArtifact) ([]byte, error) {
	var doc struct {
		Scanner   string `json:"scanner"`
		TargetRef string `json:"target_ref"`
		ReleaseID string `json:"release_id"`
		Findings  []struct {
			Vulnerability string `json:"vulnerability"`
			Component     string `json:"component"`
			Severity      string `json:"severity"`
			State         string `json:"state"`
		} `json:"findings"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("scan payload must use Evydence generic vulnerability scan JSON")
	}
	doc.Scanner = firstNonEmpty(doc.Scanner, scanner)
	doc.TargetRef = firstNonEmpty(doc.TargetRef, targetRef)
	if doc.TargetRef == "" && artifact.Digest != "" {
		doc.TargetRef = "artifact-digest:" + artifact.Digest
	}
	doc.ReleaseID = releaseID
	if strings.TrimSpace(doc.Scanner) == "" || strings.TrimSpace(doc.TargetRef) == "" {
		return nil, errors.New("scan payload requires scanner and target_ref; use --scan-scanner and --target-ref when the file omits them")
	}
	if doc.Findings == nil {
		return nil, errors.New("scan payload requires findings")
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func releaseUploadIdempotencyPrefix(cfg releaseUploadConfig, artifact releaseUploadArtifact, sbom, scan, vex json.RawMessage) string {
	parts := []string{
		cfg.ProductID, cfg.ProductName, cfg.ProductSlug,
		cfg.ReleaseID, cfg.ReleaseVersion,
		cfg.ArtifactID, artifact.Name, artifact.Digest,
		hashBytes(sbom), hashBytes(scan), hashBytes(vex),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "release-evidence-" + hex.EncodeToString(sum[:8])
}

func postReleaseUploadJSON(ctx context.Context, client *http.Client, cfg releaseUploadConfig, path, idem string, payload any, placeholderID string) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return postReleaseUploadRaw(ctx, client, cfg, path, idem, body, placeholderID)
}

func postReleaseUploadRaw(ctx context.Context, client *http.Client, cfg releaseUploadConfig, path, idem string, body []byte, placeholderID string) (string, error) {
	if cfg.DryRun {
		fmt.Printf("dry-run: would POST %s idempotency=%s payload_hash=%s\n", path, idem, hashBytes(body))
		return placeholderID, nil
	}
	response, err := postRawEvydence(ctx, client, cfg.APIURL, cfg.APIKey, path, idem, body)
	if err != nil {
		return "", err
	}
	id, err := responseDataID(response)
	if err != nil {
		return "", err
	}
	fmt.Println("uploaded " + path + ": " + id)
	return id, nil
}

func printReleaseUploadNextSteps(apiURL, releaseID string) {
	reference := "/v1/reports/release-readiness?release_id=" + releaseID
	if strings.TrimSpace(apiURL) != "" {
		if base, err := cleanAPIURL(apiURL); err == nil {
			reference = base + "/v1/reports/release-readiness?release_id=" + url.QueryEscape(releaseID)
		}
	}
	fmt.Println("next: read release readiness at " + reference)
	fmt.Println("next: verify release bundle with GET /v1/release-bundles/{id}/verify after bundle creation")
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

func getEvydence(ctx context.Context, client *http.Client, apiURL, apiKey, path string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	baseURL, err := cleanAPIURL(apiURL)
	if err != nil {
		return nil, err
	}
	// #nosec G704 -- this CLI intentionally sends requests to an operator-specified Evydence API URL after scheme and host validation.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
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

type apiRequestError struct {
	status int
	code   string
	detail string
}

func (e apiRequestError) Error() string {
	if e.code != "" {
		return fmt.Sprintf("evydence API request failed: status=%d code=%s detail=%s", e.status, e.code, e.detail)
	}
	return fmt.Sprintf("evydence API request failed: status=%d detail=%s", e.status, e.detail)
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
	return apiRequestError{status: status, code: code, detail: detail}
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
