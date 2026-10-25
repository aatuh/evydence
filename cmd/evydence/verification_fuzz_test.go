package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

func cliFuzzJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func cliFuzzZIP(t testing.TB, entries []archiveEntry, method uint16) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := zip.FileHeader{Name: entry.name, Method: method}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// Check both declared and actual inflation before asking the production CLI
// to read the archive again. Entry names are never extracted or opened as paths.
func cliFuzzZIPWithinBudget(raw []byte) bool {
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return true // Exercise production rejection of malformed ZIP structure.
	}
	if len(reader.File) > 16 {
		return false
	}
	var expanded int64
	for _, file := range reader.File {
		if file.UncompressedSize64 > 128<<10 {
			return false
		}
		stream, err := file.Open()
		if err != nil {
			continue
		}
		count, readErr := io.Copy(io.Discard, io.LimitReader(stream, (128<<10)+1))
		closeErr := stream.Close()
		if count > 128<<10 || closeErr != nil {
			return false
		}
		expanded += count
		if expanded > 512<<10 {
			return false
		}
		if readErr != nil {
			continue // Bounded CRC/format errors still reach the production reader.
		}
	}
	return true
}

func FuzzCustomerPackageArchive(f *testing.F) {
	manifest := cliFuzzJSON(f, testCustomerPackageManifest())
	parsed, err := verifyCustomerPackageManifestBytes(manifest)
	if err != nil {
		f.Fatal(err)
	}
	entries := []archiveEntry{
		{name: "manifest.json", body: manifest, mode: 0o600},
		{name: "package.json", body: cliFuzzJSON(f, map[string]any{"id": parsed.PackageID, "manifest_hash": parsed.ManifestHash}), mode: 0o600},
		{name: "verification.json", body: cliFuzzJSON(f, map[string]any{"package_id": parsed.PackageID, "manifest_hash": parsed.ManifestHash}), mode: 0o600},
	}
	baseline := cliFuzzZIP(f, entries, zip.Store)
	path := filepath.Join(f.TempDir(), "package.zip")
	cliFuzzWrite(f, path, baseline)
	positive, err := readCustomerPackageArchive(path)
	if err != nil || verifyCustomerPackageArchiveMetadata(positive, parsed) != nil {
		f.Fatalf("positive isolated package ZIP rejected: %v", err)
	}
	for _, mode := range []uint8{0, 1, 2, 3} {
		f.Add(baseline, mode)
	}
	f.Add(cliFuzzZIP(f, entries, zip.Deflate), uint8(0))
	f.Add([]byte("not a ZIP"), uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 128<<10 || !cliFuzzZIPWithinBudget(raw) {
			return
		}
		cliFuzzWrite(t, path, raw)
		first, firstErr := readCustomerPackageArchive(path)
		again, againErr := readCustomerPackageArchive(path)
		if (firstErr == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) {
			t.Fatal("ZIP reader decision is not repeatable")
		}
		if firstErr == nil && len(first.Manifest) <= 16<<10 && jsonbounds.Validate(first.Manifest, jsonbounds.Limits{MaxDepth: 12, MaxObjectKeys: 64, MaxArrayItems: 64, MaxStringBytes: 1024}) == nil {
			if contents, err := verifyCustomerPackageManifestBytes(first.Manifest); err == nil && verifyCustomerPackageArchiveMetadata(first, contents) == nil {
				changed := first
				changed.Metadata = make(map[string]any, len(first.Metadata))
				for key, value := range first.Metadata {
					changed.Metadata[key] = value
				}
				changed.Metadata["manifest_hash"] = contents.ManifestHash + "changed"
				if verifyCustomerPackageArchiveMetadata(changed, contents) == nil {
					t.Fatal("archive metadata gained trust with a different manifest hash")
				}
			}
		}
		cliFuzzWrite(t, path, baseline)
		unchanged, err := readCustomerPackageArchive(path)
		if err != nil || !reflect.DeepEqual(positive, unchanged) || verifyCustomerPackageArchiveMetadata(unchanged, parsed) != nil {
			t.Fatal("unchanged valid ZIP lost integrity")
		}
		changed := append([]archiveEntry(nil), entries...)
		switch mode % 4 {
		case 0:
			changed = append(changed, entries[0])
		case 1:
			changed[0].name = "../manifest.json"
		case 2:
			changed[0].mode = os.ModeSymlink | 0o600
		case 3:
			changed = append(changed, archiveEntry{name: "unexpected.json", body: []byte(`{}`), mode: 0o600})
		}
		cliFuzzWrite(t, path, cliFuzzZIP(t, changed, zip.Store))
		if _, err := readCustomerPackageArchive(path); err == nil {
			t.Fatal("duplicate, traversal, symlink or unexpected archive member accepted")
		}
	})
}

func FuzzReleaseManifest(f *testing.F) {
	for _, mode := range []uint8{0, 1, 2, 3} {
		f.Add([]byte("offline release artifact"), mode)
	}
	f.Add([]byte{}, uint8(0))
	dir := f.TempDir()
	manifestPath, signaturePath, artifactPath := filepath.Join(dir, "manifest.json"), filepath.Join(dir, "signature.json"), filepath.Join(dir, "artifact.bin")
	private := cliFuzzKey()
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 16<<10 {
			return
		}
		cliFuzzWrite(t, artifactPath, raw)
		manifest := map[string]any{
			"schema_version": "evydence-release-artifacts.v1.0.0", "generated_at": "2026-10-01T12:00:00Z",
			"artifacts": []any{map[string]any{"path": "artifact.bin", "digest": hashBytes(raw), "size": len(raw)}},
		}
		cliFuzzWrite(t, manifestPath, cliFuzzJSON(t, manifest))
		canonical, hash, err := canonicalFileHash(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		value := ed25519.Sign(private, canonical)
		signature := map[string]any{"schema_version": "evydence-release-signature.v1.0.0", "manifest_hash": hash, "algorithm": "Ed25519", "public_key": base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), "signature": base64.StdEncoding.EncodeToString(value)}
		cliFuzzWrite(t, signaturePath, cliFuzzJSON(t, signature))
		verify := func() error {
			return verifyReleaseArtifactManifest([]string{"--manifest", manifestPath, "--signature", signaturePath})
		}
		if _, err := captureStdout(t, verify); err != nil {
			t.Fatalf("unchanged local release/signature/artifact rejected: %v", err)
		}
		switch mode % 4 {
		case 0:
			cliFuzzWrite(t, artifactPath, append(append([]byte(nil), raw...), 0))
		case 1:
			manifest["generated_at"] = "2026-10-01T12:00:01Z"
			cliFuzzWrite(t, manifestPath, cliFuzzJSON(t, manifest))
		case 2:
			value[0] ^= 1
			signature["signature"] = base64.StdEncoding.EncodeToString(value)
			cliFuzzWrite(t, signaturePath, cliFuzzJSON(t, signature))
		case 3:
			signature["manifest_hash"] = hash + "changed"
			cliFuzzWrite(t, signaturePath, cliFuzzJSON(t, signature))
		}
		if _, err := captureStdout(t, verify); err == nil {
			t.Fatal("changed artifact bytes, manifest, signature or digest accepted")
		}
	})
}

func cliFuzzWrite(t testing.TB, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cliFuzzKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("Evydence EVY-1109 synthetic offline key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func cliFuzzSignedBundle(t testing.TB, manifest map[string]any) offlineEvidenceBundle {
	t.Helper()
	hash, err := canonicalJSONBytesHash(cliFuzzJSON(t, manifest))
	if err != nil {
		t.Fatal(err)
	}
	private := cliFuzzKey()
	return offlineEvidenceBundle{
		Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{"signature"},
		Signatures:  []offlineSignature{{ID: "signature", KeyID: "key", Algorithm: "Ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(hash))), CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}},
		SigningKeys: []offlineSigningKey{{ID: "key", Algorithm: "Ed25519", Status: "active", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}},
	}
}

func TestPackageCoverageRejectsUnspecifiedBundleEvidence(t *testing.T) {
	if err := verifyCustomerPackageEvidenceCoverage(nil, map[string]any{}); err != nil {
		t.Fatalf("empty package evidence set must not require bundle coverage: %v", err)
	}
	manifest := cliFuzzJSON(t, testCustomerPackageManifest())
	parsed, err := verifyCustomerPackageManifestBytes(manifest)
	if err != nil || len(parsed.EvidenceIDs) == 0 {
		t.Fatalf("positive package manifest rejected: %v", err)
	}
	ids := make([]any, len(parsed.EvidenceIDs))
	for i, id := range parsed.EvidenceIDs {
		ids[i] = id
	}
	for _, candidate := range []struct {
		name    string
		present bool
		value   any
		valid   bool
	}{
		{"explicit coverage", true, ids, true},
		{"missing", false, nil, false},
		{"null", true, nil, false},
		{"empty", true, []any{}, false},
		{"wrong type", true, parsed.EvidenceIDs[0], false},
		{"no usable ids", true, []any{nil, 17, true, " "}, false},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			bundleManifest := map[string]any{"bundle_version": "evidence-bundle.v1.0.0"}
			if candidate.present {
				bundleManifest["evidence_ids"] = candidate.value
			}
			bundle := cliFuzzSignedBundle(t, bundleManifest)
			if verified, err := verifyEvidenceBundleStruct(bundle); err != nil || !verified.Signed {
				t.Fatalf("control signature/hash failed before coverage check: %v", err)
			}
			dir := t.TempDir()
			manifestPath, bundlePath := filepath.Join(dir, "package.json"), filepath.Join(dir, "bundle.json")
			cliFuzzWrite(t, manifestPath, manifest)
			cliFuzzWrite(t, bundlePath, cliFuzzJSON(t, bundle))
			output, err := captureStdout(t, func() error {
				return verifyCustomerPackage([]string{"--manifest", manifestPath, "--bundle", bundlePath, "--expected-signing-key-id", "key"})
			})
			if candidate.valid {
				if err != nil || !strings.Contains(output, "verified with signature") {
					t.Fatalf("valid scoped signed bundle rejected: %v", err)
				}
			} else if err == nil || strings.Contains(output, "customer package verified") {
				t.Fatal("CLI reported verified package evidence coverage without a usable bundle evidence-id set")
			}
		})
	}
}

func FuzzCustomerPackageManifest(f *testing.F) {
	baseline := cliFuzzJSON(f, testCustomerPackageManifest())
	if _, err := verifyCustomerPackageManifestBytes(baseline); err != nil {
		f.Fatalf("positive manifest rejected: %v", err)
	}
	for _, mode := range []uint8{0, 1, 2, 3} {
		f.Add(baseline, mode)
	}
	alias := bytes.Replace(baseline, []byte(`"package_id"`), []byte(`"PACKAGE_ID"`), 1)
	if _, err := verifyCustomerPackageManifestBytes(alias); err != nil {
		f.Fatalf("existing decoder key-case compatibility rejected: %v", err)
	}
	f.Add(alias, uint8(0))
	f.Add([]byte(`{}`), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 16<<10 || jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 12, MaxObjectKeys: 64, MaxArrayItems: 64, MaxStringBytes: 1024}) != nil {
			return
		}
		first, firstErr := verifyCustomerPackageManifestBytes(raw)
		again, againErr := verifyCustomerPackageManifestBytes(raw)
		if (firstErr == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) {
			t.Fatal("manifest decision is not repeatable")
		}
		if firstErr != nil {
			return
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		roundTrip, err := verifyCustomerPackageManifestBytes(cliFuzzJSON(t, document))
		if err != nil || !reflect.DeepEqual(first, roundTrip) {
			t.Fatal("canonical serialization changed manifest identity/hash")
		}
		// Repeat an actual decoded key. A canonical spelling is not always
		// present when the existing typed decoder accepts a key-case alias.
		duplicateKey, selected := "", false
		for key := range document {
			if !selected || key < duplicateKey {
				duplicateKey, selected = key, true
			}
		}
		if !selected {
			t.Fatal("accepted manifest has no object keys")
		}
		prefix := append([]byte{'{'}, cliFuzzJSON(t, duplicateKey)...)
		prefix = append(prefix, []byte(":null,")...)
		duplicate := append(prefix, bytes.TrimSpace(raw)[1:]...)
		if _, err := verifyCustomerPackageManifestBytes(duplicate); err == nil {
			t.Fatal("duplicate decoded manifest key accepted")
		}
		ids := make([]any, len(first.EvidenceIDs))
		for i, id := range first.EvidenceIDs {
			ids[i] = id
		}
		bundle := cliFuzzSignedBundle(t, map[string]any{"bundle_version": "evidence-bundle.v1.0.0", "evidence_ids": ids})
		if verified, err := verifyEvidenceBundleStruct(bundle); err != nil || !verified.Signed {
			t.Fatalf("positive signed evidence bundle rejected: %v", err)
		}
		if err := verifyCustomerPackageEvidenceCoverage(first.EvidenceIDs, bundle.Manifest); err != nil {
			t.Fatal("matching evidence-id coverage rejected")
		}
		switch mode % 4 {
		case 0:
			document["package_id"] = first.PackageID + "-different"
			if _, err := verifyCustomerPackageManifestBytes(cliFuzzJSON(t, document)); err == nil {
				t.Fatal("mismatched package identity accepted")
			}
		case 1:
			document["payload_ref"] = "synthetic-prohibited-value"
			if _, err := verifyCustomerPackageManifestBytes(cliFuzzJSON(t, document)); err == nil {
				t.Fatal("prohibited raw-payload reference accepted")
			}
		case 2:
			value, err := base64.StdEncoding.DecodeString(bundle.Signatures[0].Value)
			if err != nil {
				t.Fatal(err)
			}
			value[0] ^= 1
			bundle.Signatures[0].Value = base64.StdEncoding.EncodeToString(value)
			if _, err := verifyEvidenceBundleStruct(bundle); err == nil {
				t.Fatal("tampered included evidence-bundle signature accepted")
			}
		case 3:
			if len(first.EvidenceIDs) > 0 {
				if err := verifyCustomerPackageEvidenceCoverage(first.EvidenceIDs, map[string]any{}); err == nil {
					t.Fatal("unspecified evidence-id coverage accepted")
				}
			}
		}
	})
}
