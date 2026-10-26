package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	d "github.com/aatuh/evydence/internal/experimental/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

type transparencyFuzzVector struct {
	LeafHash       string   `json:"leaf_hash"`
	RootHash       string   `json:"root_hash"`
	LeafIndex      int      `json:"leaf_index"`
	TreeSize       int      `json:"tree_size"`
	InclusionProof []string `json:"inclusion_proof"`
}

// Independent recursive RFC6962 tree construction complements the production
// verifier's iterative index/last-node traversal. Trees stay at 16 leaves.
func transparencyFuzzRoot(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	split := 1
	for split*2 < len(leaves) {
		split *= 2
	}
	left, right := transparencyFuzzRoot(leaves[:split]), transparencyFuzzRoot(leaves[split:])
	digest := sha256.Sum256(append(append([]byte{1}, left...), right...))
	return digest[:]
}

func transparencyFuzzProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	split := 1
	for split*2 < len(leaves) {
		split *= 2
	}
	if index < split {
		return append(transparencyFuzzProof(leaves[:split], index), transparencyFuzzRoot(leaves[split:]))
	}
	return append(transparencyFuzzProof(leaves[split:], index-split), transparencyFuzzRoot(leaves[:split]))
}

func transparencyFuzzChangedDigest(value string) string {
	if value[len(value)-1] == '0' {
		return value[:len(value)-1] + "1"
	}
	return value[:len(value)-1] + "0"
}

func FuzzPublicTransparencyProof(f *testing.F) {
	raw, err := os.ReadFile("../../../testdata/verification/rfc6962-tree-size-3.v1.json")
	if err != nil {
		f.Fatal(err)
	}
	var pinned transparencyFuzzVector
	if err := json.Unmarshal(raw, &pinned); err != nil || !VerifyPublicTransparencyProof(pinned.LeafHash, pinned.RootHash, pinned.LeafIndex, pinned.TreeSize, pinned.InclusionProof) {
		f.Fatalf("pinned irregular-tree proof rejected: %v", err)
	}
	for _, mode := range []uint8{0, 1, 2, 3, 4, 6, 7, 8, 15, 19, 255} {
		f.Add(raw, mode)
	}
	f.Add([]byte(`{}`), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 16<<10 || jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 8, MaxObjectKeys: 16, MaxArrayItems: 64, MaxStringBytes: 128}) != nil {
			return
		}
		var candidate transparencyFuzzVector
		if json.Unmarshal(raw, &candidate) == nil && len(candidate.InclusionProof) <= MaxPublicTransparencyProofNodes {
			first := VerifyPublicTransparencyProof(candidate.LeafHash, candidate.RootHash, candidate.LeafIndex, candidate.TreeSize, candidate.InclusionProof)
			if first != VerifyPublicTransparencyProof(candidate.LeafHash, candidate.RootHash, candidate.LeafIndex, candidate.TreeSize, candidate.InclusionProof) {
				t.Fatal("proof decision is not repeatable")
			}
			if first && VerifyPublicTransparencyProof(candidate.LeafHash, transparencyFuzzChangedDigest(candidate.RootHash), candidate.LeafIndex, candidate.TreeSize, candidate.InclusionProof) {
				t.Fatal("changed root passed the same proof")
			}
		}
		if !VerifyPublicTransparencyProof(pinned.LeafHash, pinned.RootHash, pinned.LeafIndex, pinned.TreeSize, pinned.InclusionProof) {
			t.Fatal("unchanged pinned vector lost validity")
		}
		count := 1 + int(mode)%16
		index := (int(mode) + len(raw)) % count
		leaves := make([][]byte, count)
		for i := range leaves {
			digest := sha256.Sum256(append([]byte{0, byte(i)}, raw...))
			leaves[i] = digest[:]
		}
		leaf := "sha256:" + hex.EncodeToString(leaves[index])
		root := "sha256:" + hex.EncodeToString(transparencyFuzzRoot(leaves))
		proof := []string{}
		for _, node := range transparencyFuzzProof(leaves, index) {
			proof = append(proof, "sha256:"+hex.EncodeToString(node))
		}
		if !VerifyPublicTransparencyProof(leaf, root, index, count, proof) || VerifyPublicTransparencyProof(leaf, root, index, count, append(append([]string(nil), proof...), leaf)) {
			t.Fatal("recursive reference proof or exact proof length disagrees with production")
		}
		now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		entry := d.PublicTransparencyLogEntry{ID: "entry", TenantID: "tenant", LogID: "log", CheckpointID: "checkpoint", MerkleBatchID: "batch", ExternalID: "external", EntryHash: leaf, State: "published", SchemaVersion: d.PublicTransparencyEntryVersion, CreatedAt: now.Add(-time.Hour)}
		input := PublicTransparencyProofInput{LeafHash: leaf, RootHash: root, LeafIndex: index, TreeSize: count, InclusionProof: proof}
		positive, err := BuildPublicTransparencyVerification(entry, input, "", now)
		if err != nil || positive.State != "inclusion_verified" {
			t.Fatalf("native entry binding rejected a valid generated proof: %v", err)
		}
		input.LeafHash = transparencyFuzzChangedDigest(leaf)
		changed, err := BuildPublicTransparencyVerification(entry, input, "", now)
		if err == nil && changed.State == "inclusion_verified" {
			t.Fatal("proof for a different published leaf gained trust")
		}
	})
}
