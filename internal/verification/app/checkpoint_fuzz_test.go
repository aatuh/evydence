package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func nativeFuzzCheckpoint(t testing.TB, raw []byte, mode uint8, release bool) *nativeFuzzPorts {
	t.Helper()
	s := &nativeFuzzPorts{nativeFuzzChain: nativeFuzzAudit(t, raw, 1+int(mode%8), false)}
	if release {
		s.subject = verificationapp.SubjectReference{TenantID: "tenant", Type: "release_bundle", ID: "bundle", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
		// Include both the historical zero/prefix checkpoint and a covered
		// tail. The full chain must be inspected even for a shorter prefix.
		sequence := int64(int(mode) % (len(s.pages) + 1))
		head := ""
		if sequence != 0 {
			head = s.pages[sequence-1].Entries[0].EntryHash
		}
		manifest := map[string]any{"chain_checkpoint": map[string]any{"sequence": json.Number(strconv.FormatInt(sequence, 10)), "head_hash": head}, "content": integrityFuzzDigest(raw)}
		hash, err := (integrityFuzzHasher{}).Hash(manifest)
		if err != nil {
			t.Fatal(err)
		}
		sigs, keys := integrityFuzzSigning(t, s.subject, []byte(hash), nativeFuzzNow)
		s.bundle = verificationapp.ReleaseBundleVerificationSnapshot{Subject: s.subject, Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{"signature"}, Signatures: sigs, Keys: keys}
	} else {
		s.subject = verificationapp.SubjectReference{TenantID: "tenant", Type: "merkle_batch", ID: "batch"}
		count := 1 + int(mode)%len(s.pages)
		leaves := make([]verificationapp.AuditChainLeaf, 0, count)
		hashes := make([]string, 0, count)
		for _, page := range s.pages[:count] {
			e := page.Entries[0]
			leaves = append(leaves, verificationapp.AuditChainLeaf{Sequence: e.Sequence, EntryHash: e.EntryHash})
			hashes = append(hashes, e.EntryHash)
		}
		root := integrityFuzzMerkleRoot(hashes)
		sigs, keys := integrityFuzzSigning(t, s.subject, []byte(root), nativeFuzzNow)
		s.merkle = verificationapp.MerkleVerificationSnapshot{Subject: s.subject, Leaves: leaves, Signatures: sigs, Keys: keys, Batch: verificationdomain.MerkleBatch{ID: "batch", TenantID: "tenant", FromSequence: 1, ToSequence: int64(count), EntryCount: count, LeafHashes: hashes, RootHash: root, SignatureRefs: []string{"signature"}}}
	}
	return s
}

func nativeFuzzRunCheckpoint(t *testing.T, ctx context.Context, s *nativeFuzzPorts, actorTenant string, release bool) (verificationdomain.VerificationResult, error) {
	t.Helper()
	actor := nativeFuzzActor()
	actor.TenantID = actorTenant
	clock := application.ClockFunc(func() time.Time { return nativeFuzzNow })
	if release {
		c, err := verificationapp.NewReleaseManifestCheckpointCommands(verificationapp.ReleaseManifestCheckpointConfig{Transactions: s, Authorizer: s, Hasher: integrityFuzzHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
	}
	c, err := verificationapp.NewMerkleCheckpointVerificationCommands(verificationapp.MerkleCheckpointVerificationConfig{Transactions: s, Authorizer: s, Hasher: integrityFuzzHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: nativeFuzzIDs()})
	if err != nil {
		t.Fatal(err)
	}
	return c.VerifyMerkleCheckpoint(ctx, actor, "batch")
}

func nativeFuzzCheckpointProperty(t *testing.T, raw []byte, mode uint8, release bool) {
	t.Helper()
	owner, ownerID := "merkle_batch", "batch"
	if release {
		owner, ownerID = "release_bundle", "bundle"
	}
	nativeFuzzSnapshotCommandProperty(t, func() *nativeFuzzPorts {
		return nativeFuzzCheckpoint(t, raw, mode, release)
	}, owner, ownerID, "passed", mode)
	s := nativeFuzzCheckpoint(t, raw, mode, release)
	before := nativeFuzzJSON(t, []any{s.pages, s.merkle, s.bundle})
	positive, err := nativeFuzzRunCheckpoint(t, t.Context(), s, "tenant", release)
	if err != nil {
		t.Fatalf("signed native checkpoint rejected: %v", err)
	}
	kind, id := "audit_chain_checkpoint", "batch"
	profile := verificationdomain.VerificationProfileAuditChainMerkleCheckpoint
	if release {
		kind, id, profile = "audit_chain_release_manifest", "bundle", verificationdomain.VerificationProfileAuditChainReleaseManifest
	}
	nativeFuzzAssertReceipt(t, s, positive, kind, id, "passed")
	if positive.Profile.ID != profile || positive.Profile.TransparencyProof != "not_evaluated" || s.reads != len(s.pages)+1 || len(s.requests) != 2 || !s.requests[0].ScopeOnly || !s.requests[1].TenantWide {
		t.Fatal("checkpoint lost full-chain, authorization or profile semantics")
	}
	again, err := nativeFuzzRunCheckpoint(t, t.Context(), nativeFuzzCheckpoint(t, raw, mode, release), "tenant", release)
	if err != nil || !reflect.DeepEqual(positive, again) {
		t.Fatal("native checkpoint receipt is not repeatable")
	}
	changed := nativeFuzzCheckpoint(t, raw, mode, release)
	switch mode % 10 {
	case 0:
		// This can be outside a signed prefix: the full canonical chain still
		// must fail while the signature itself remains mathematically valid.
		changed.pages[len(changed.pages)-1].Entries[0].PayloadHash += "changed"
	case 1:
		if release {
			changed.bundle.Signatures[0].Value = integrityFuzzTamperSignature(t, changed.bundle.Signatures[0].Value)
		} else {
			changed.merkle.Signatures[0].Value = integrityFuzzTamperSignature(t, changed.merkle.Signatures[0].Value)
		}
	case 2:
		if release {
			changed.bundle.Signatures[0].SubjectID = "foreign"
		} else {
			changed.merkle.Signatures[0].SubjectID = "foreign"
		}
	case 3:
		if release {
			changed.bundle.Manifest["chain_checkpoint"] = map[string]any{"sequence": json.Number(strconv.Itoa(len(changed.pages) + 1)), "head_hash": "missing"}
			// Re-sign the internally valid but uncovered manifest. A valid
			// signature cannot substitute for native chain coverage.
			hash, hashErr := (integrityFuzzHasher{}).Hash(changed.bundle.Manifest)
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			changed.bundle.ManifestHash = hash
			changed.bundle.Signatures, changed.bundle.Keys = integrityFuzzSigning(t, changed.subject, []byte(hash), nativeFuzzNow)
		} else {
			// The alternate projection is internally signed and consistent.
			// It must still bind to the independently inspected chain pages.
			for i := range changed.merkle.Leaves {
				hash := integrityFuzzDigest([]byte("alternate-" + strconv.Itoa(i)))
				changed.merkle.Leaves[i].EntryHash, changed.merkle.Batch.LeafHashes[i] = hash, hash
			}
			changed.merkle.Batch.RootHash = integrityFuzzMerkleRoot(changed.merkle.Batch.LeafHashes)
			changed.merkle.Signatures, changed.merkle.Keys = integrityFuzzSigning(t, changed.subject, []byte(changed.merkle.Batch.RootHash), nativeFuzzNow)
		}
	case 4:
		changed.pages = changed.pages[:len(changed.pages)-1]
	case 5:
		changed.subject.TenantID = "foreign"
	case 6:
		changed.view.TenantID = "foreign"
	case 7:
		if release {
			changed.bundle.Subject.ID = "other"
		} else {
			changed.merkle.Subject.ID = "other"
		}
	case 8:
		if release {
			changed.bundle.Keys[0].TenantID = "foreign"
		} else {
			changed.merkle.Keys[0].TenantID = "foreign"
		}
	case 9:
		changed.pages[0].BytesRead = verificationapp.MaxAuditChainVerificationBytes + 1
	}
	decision, err := nativeFuzzRunCheckpoint(t, t.Context(), changed, "tenant", release)
	if err == nil || decision.Result.String() == "passed" {
		t.Fatal("changed native checkpoint passed")
	}
	if errors.Is(err, verificationapp.ErrVerificationFailed) {
		nativeFuzzAssertReceipt(t, changed, decision, kind, id, "failed")
	} else {
		nativeFuzzAssertNoWrites(t, changed)
	}
	if mode%10 == 5 || mode%10 == 6 {
		if changed.payloads+changed.reads != 0 {
			t.Fatal("foreign checkpoint read payload or pages")
		}
	}
	if nativeFuzzJSON(t, []any{s.pages, s.merkle, s.bundle}) != before {
		t.Fatal("checkpoint command mutated immutable source material")
	}
	failed := nativeFuzzCheckpoint(t, raw, mode, release)
	failed.fail = []string{"result", "audit", "outbox", "commit"}[mode%4]
	if _, err := nativeFuzzRunCheckpoint(t, t.Context(), failed, "tenant", release); !errors.Is(err, errNativeFuzzWrite) {
		t.Fatal("receipt failure was not returned")
	}
	nativeFuzzAssertNoWrites(t, failed)
	foreign := nativeFuzzCheckpoint(t, raw, mode, release)
	if _, err := nativeFuzzRunCheckpoint(t, t.Context(), foreign, "foreign", release); !errors.Is(err, verificationapp.ErrNotFound) || foreign.payloads+foreign.reads != 0 {
		t.Fatal("foreign actor read a native checkpoint")
	}
	nativeFuzzAssertNoWrites(t, foreign)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	canceled := nativeFuzzCheckpoint(t, raw, mode, release)
	if _, err := nativeFuzzRunCheckpoint(t, ctx, canceled, "tenant", release); !errors.Is(err, context.Canceled) || canceled.payloads+canceled.reads != 0 {
		t.Fatal("canceled checkpoint command read a snapshot")
	}
}

func FuzzMerkleCheckpointIntegrity(f *testing.F) {
	for mode := uint8(0); mode < 10; mode++ {
		f.Add([]byte("native Merkle checkpoint"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) <= 4096 {
			nativeFuzzCheckpointProperty(t, raw, mode, false)
		}
	})
}

func FuzzReleaseManifestCheckpointIntegrity(f *testing.F) {
	for mode := uint8(0); mode < 10; mode++ {
		f.Add([]byte("native release checkpoint"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) <= 4096 {
			nativeFuzzCheckpointProperty(t, raw, mode, true)
		}
	})
}
