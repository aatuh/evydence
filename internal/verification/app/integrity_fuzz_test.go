package app_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type integrityFuzzHasher struct{}

func (integrityFuzzHasher) Hash(value any) (string, error) {
	return application.NormalizedJSONHash(value)
}

func integrityFuzzDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func integrityFuzzSigning(t testing.TB, subject verificationapp.SubjectReference, payload []byte, now time.Time) ([]verificationdomain.Signature, []verificationdomain.SigningKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("Evydence EVY-1109 synthetic integrity key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	active, err := verificationdomain.ParseSigningKeyStatus("active")
	if err != nil {
		t.Fatal(err)
	}
	return []verificationdomain.Signature{{
		ID: "signature", TenantID: subject.TenantID, SubjectType: subject.Type, SubjectID: subject.ID,
		KeyID: "key", Algorithm: "Ed25519", Value: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload)), CreatedAt: now.Add(-time.Minute),
	}}, []verificationdomain.SigningKey{{
		ID: "key", TenantID: subject.TenantID, Algorithm: "Ed25519", Status: active,
		PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), CreatedAt: now.Add(-time.Hour), ValidFrom: now.Add(-time.Hour),
	}}
}

func integrityFuzzPassed(inspection verificationapp.SubjectInspection) bool {
	if len(inspection.Checks) == 0 {
		return false
	}
	for _, check := range inspection.Checks {
		if check.Result != "passed" {
			return false
		}
	}
	return true
}

func integrityFuzzTamperSignature(t *testing.T, value string) string {
	t.Helper()
	raw, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatal("invalid positive signature vector")
	}
	raw[0] ^= 1
	return base64.RawStdEncoding.EncodeToString(raw)
}

// The legacy odd-leaf vector anchors this independent recursive projection.
func integrityFuzzMerkleRoot(leaves []string) string {
	if len(leaves) == 1 {
		return leaves[0]
	}
	parents := make([]string, 0, (len(leaves)+1)/2)
	for i := 0; i < len(leaves); i += 2 {
		right := leaves[i]
		if i+1 < len(leaves) {
			right = leaves[i+1]
		}
		parents = append(parents, integrityFuzzDigest([]byte(leaves[i]+"\n"+right)))
	}
	return integrityFuzzMerkleRoot(parents)
}

func FuzzMerkleBatchIntegrity(f *testing.F) {
	if integrityFuzzMerkleRoot([]string{"one", "two", "three"}) != "sha256:6e444ebe3af93e744977821c234b40e5b33c1f358cddfbfb49f17fcca84300f0" {
		f.Fatal("odd-leaf reference vector changed")
	}

	for _, mode := range []uint8{0, 1, 2, 3, 15, 255} {
		f.Add([]byte("native signed Merkle batch"), mode)
	}
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		subject := verificationapp.SubjectReference{TenantID: "tenant", Type: "merkle_batch", ID: "batch"}
		count := 1 + int(mode)%16
		leaves := make([]verificationapp.AuditChainLeaf, count)
		hashes := make([]string, count)
		for index := range leaves {
			hashes[index] = integrityFuzzDigest(append([]byte{byte(index)}, raw...))
			leaves[index] = verificationapp.AuditChainLeaf{Sequence: int64(index + 1), EntryHash: hashes[index]}
		}
		root := integrityFuzzMerkleRoot(hashes)
		signatures, keys := integrityFuzzSigning(t, subject, []byte(root), now)
		snapshot := verificationapp.MerkleVerificationSnapshot{
			Subject: subject, Leaves: leaves, Signatures: signatures, Keys: keys,
			Batch: verificationdomain.MerkleBatch{ID: subject.ID, TenantID: subject.TenantID, FromSequence: 1, ToSequence: int64(count), EntryCount: count, LeafHashes: hashes, RootHash: root, SignatureRefs: []string{"signature"}},
		}
		positive, err := verificationapp.InspectMerkleBatch(snapshot, now, localed25519.PayloadVerifier{})
		if err != nil || !integrityFuzzPassed(positive) {
			t.Fatalf("real signed Merkle positive vector rejected: %v", err)
		}
		again, err := verificationapp.InspectMerkleBatch(snapshot, now, localed25519.PayloadVerifier{})
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("Merkle inspection is not repeatable")
		}
		changed := snapshot
		changed.Batch.LeafHashes = append([]string(nil), hashes...)
		changed.Leaves = append([]verificationapp.AuditChainLeaf(nil), leaves...)
		changed.Signatures = append([]verificationdomain.Signature(nil), signatures...)
		switch mode % 4 {
		case 0:
			changed.Batch.LeafHashes[0] += "changed"
		case 1:
			changed.Leaves[0].Sequence++
		case 2:
			changed.Signatures[0].Value = integrityFuzzTamperSignature(t, signatures[0].Value)
		case 3:
			changed.Signatures[0].SubjectID += "-different"
		}
		decision, err := verificationapp.InspectMerkleBatch(changed, now, localed25519.PayloadVerifier{})
		if err == nil && integrityFuzzPassed(decision) {
			t.Fatal("changed coverage, leaf, signature or subject binding passed")
		}
		unchanged, err := verificationapp.InspectMerkleBatch(snapshot, now, localed25519.PayloadVerifier{})
		if err != nil || !reflect.DeepEqual(positive, unchanged) {
			t.Fatal("tamper construction aliased the original Merkle snapshot")
		}
	})
}

func FuzzReleaseBundleIntegrity(f *testing.F) {
	for _, sequence := range []int64{-1, 0, 1, 9007199254740993, 9223372036854775807} {
		f.Add([]byte("native release manifest"), sequence, uint8(0))
	}
	for _, mode := range []uint8{1, 2, 3} {
		f.Add([]byte{}, int64(1), mode)
	}
	f.Fuzz(func(t *testing.T, raw []byte, sequence int64, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		subject := verificationapp.SubjectReference{TenantID: "tenant", Type: "release_bundle", ID: "bundle", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
		head := integrityFuzzDigest(raw)
		manifest := map[string]any{"content": base64.RawStdEncoding.EncodeToString(raw), "chain_checkpoint": map[string]any{"sequence": json.Number(strconv.FormatInt(sequence, 10)), "head_hash": head}}
		gotSequence, gotHead, ok := verificationapp.ReleaseManifestAuditChainCheckpoint(manifest)
		if !ok || gotSequence != sequence || gotHead != head {
			t.Fatal("native checkpoint parser lost integer identity")
		}
		hash, err := (integrityFuzzHasher{}).Hash(manifest)
		if err != nil {
			t.Fatal(err)
		}
		signatures, keys := integrityFuzzSigning(t, subject, []byte(hash), now)
		snapshot := verificationapp.ReleaseBundleVerificationSnapshot{Subject: subject, Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{"signature"}, Signatures: signatures, Keys: keys}
		positive, err := verificationapp.InspectReleaseBundle(snapshot, now, integrityFuzzHasher{}, localed25519.PayloadVerifier{})
		if err != nil || !integrityFuzzPassed(positive) {
			t.Fatalf("real signed release positive vector rejected: %v", err)
		}
		again, err := verificationapp.InspectReleaseBundle(snapshot, now, integrityFuzzHasher{}, localed25519.PayloadVerifier{})
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("release inspection is not repeatable")
		}
		changed := snapshot
		changed.Manifest = make(map[string]any, len(manifest))
		for key, value := range manifest {
			changed.Manifest[key] = value
		}
		changed.Signatures = append([]verificationdomain.Signature(nil), signatures...)
		switch mode % 4 {
		case 0:
			changed.Manifest["content"] = "changed:" + manifest["content"].(string)
		case 1:
			changed.ManifestHash += "changed"
		case 2:
			changed.Signatures[0].Value = integrityFuzzTamperSignature(t, signatures[0].Value)
		case 3:
			changed.Signatures[0].SubjectID += "-different"
		}
		decision, err := verificationapp.InspectReleaseBundle(changed, now, integrityFuzzHasher{}, localed25519.PayloadVerifier{})
		if err == nil && integrityFuzzPassed(decision) {
			t.Fatal("changed manifest, hash, signature or subject binding passed")
		}
		unchanged, err := verificationapp.InspectReleaseBundle(snapshot, now, integrityFuzzHasher{}, localed25519.PayloadVerifier{})
		if err != nil || !reflect.DeepEqual(positive, unchanged) {
			t.Fatal("tamper construction aliased the original release snapshot")
		}
	})
}
