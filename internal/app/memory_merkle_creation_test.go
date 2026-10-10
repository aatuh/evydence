package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type memoryMerkleSigner interface {
	SignMerkleRoot(context.Context, verificationapp.SigningRequest) (verificationapp.SigningResult, error)
}

func memoryMerkleCreationFixture(t *testing.T) (*memoryUnitOfWork, verificationapp.MerkleCreationReader, verificationapp.TransparencyCheckpointReader, verificationapp.TransparencyCheckpointScopeLocker) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Integrity.(verificationapp.MerkleCreationReader)
	if !ok {
		t.Fatal("memory integrity lacks focused Merkle creation reader")
	}
	c, ok := tx.Repositories().Integrity.(verificationapp.TransparencyCheckpointReader)
	if !ok {
		t.Fatal("memory integrity lacks focused checkpoint source")
	}
	l, ok := tx.Repositories().Integrity.(verificationapp.TransparencyCheckpointScopeLocker)
	if !ok {
		t.Fatal("memory integrity lacks ownership-only checkpoint guard")
	}
	return tx, r, c, l
}

func TestMemoryMerkleCreationReadsCurrentOrderedHashesAndCheckpointGuardIgnoresMetadata(t *testing.T) {
	tx, r, c, locker := memoryMerkleCreationFixture(t)
	tx.state.AuditEntries["tenant"] = []domain.AuditChainEntry{{TenantID: "tenant", Sequence: 2, EntryHash: "second", SubjectID: "private-ignored"}, {TenantID: "tenant", Sequence: 1, EntryHash: "first"}, {TenantID: "foreign", Sequence: 9, EntryHash: "foreign-ignored"}}
	view, err := r.LockMerkleCreationView(t.Context(), "tenant")
	if err != nil || view.TenantID != "tenant" || view.EntryCount != 2 || view.FirstSequence != 1 || view.LastSequence != 2 || view.HasEmptyHash {
		t.Fatal("Merkle view used slice order or foreign entries", err)
	}
	leaves, err := r.ReadMerkleCreationLeaves(t.Context(), "tenant", 1, 2)
	if err != nil || !reflect.DeepEqual(leaves, []verificationapp.AuditChainLeaf{{Sequence: 1, EntryHash: "first"}, {Sequence: 2, EntryHash: "second"}}) {
		t.Fatal("Merkle leaves lost bounded ordered hash projection", err)
	}
	leaves[0].EntryHash = "changed"
	if tx.state.AuditEntries["tenant"][1].EntryHash != "first" {
		t.Fatal("Merkle leaves alias stored entries")
	}
	tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", RootHash: "root", LeafHashes: []string{"private-ignored"}}
	source, err := c.ReadTransparencyCheckpointSource(t.Context(), "tenant", "batch")
	if err != nil || source.RootHash != "root" || source.ID != "batch" {
		t.Fatal("checkpoint source lost owned root", err)
	}
	v := tx.state.MerkleBatches["batch"]
	v.RootHash = strings.Repeat("x", 1025)
	tx.state.MerkleBatches[v.ID] = v
	if err := locker.LockTransparencyCheckpointScope(t.Context(), "tenant", "batch"); err != nil {
		t.Fatal("checkpoint replay inspected root metadata", err)
	}
	if value, err := c.ReadTransparencyCheckpointSource(t.Context(), "tenant", "batch"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, verificationapp.TransparencyCheckpointSource{}) {
		t.Fatal("oversized checkpoint source returned partial facts", err)
	}
	tx.state.MerkleBatches["foreign"] = domain.MerkleBatch{ID: "foreign", TenantID: "foreign", RootHash: "unselected"}
	if err := locker.LockTransparencyCheckpointScope(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign batch authorized", err)
	}
	tx.state.AuditEntries["tenant"][0].EntryHash = strings.Repeat("x", 1025)
	if value, err := r.ReadMerkleCreationLeaves(t.Context(), "tenant", 1, 2); !errors.Is(err, ErrConflict) || value != nil {
		t.Fatal("oversized leaf returned partial hashes", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.LockMerkleCreationView(ctx, "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled Merkle view accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadTransparencyCheckpointSource(t.Context(), "tenant", "batch"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed checkpoint view accepted", err)
	}
}

func TestMemoryMerkleSigningPreparesReplacementKeyWithoutPublishingAndEnforcesVersionExhaustion(t *testing.T) {
	tx, _, _ := memoryPackageSigningFixture(t)
	signer, ok := tx.Repositories().Signatures.(memoryMerkleSigner)
	if !ok {
		t.Fatal("missing Merkle signer")
	}
	key := tx.state.SigningKeys["key"]
	key.Status = "revoked"
	at := fixedNow()
	key.RevokedAt = &at
	tx.state.SigningKeys[key.ID] = key
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	request := verificationapp.SigningRequest{TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", Payload: []byte("root"), CreatedAt: at}
	v, err := signer.SignMerkleRoot(t.Context(), request)
	if err != nil || v.NewKey == nil || v.NewKey.Key.Version != 3 || v.Signature.KeyID != v.NewKey.Key.ID || len(v.NewKey.PrivateMaterial) != ed25519.PrivateKeySize {
		t.Fatal("replacement key preparation lost binding or version", err)
	}
	defer clear(v.NewKey.PrivateMaterial)
	public, err := base64.RawStdEncoding.Strict().DecodeString(v.NewKey.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(v.Signature.Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), request.Payload, signature) || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("prepared key/signature mutated repository or failed crypto", err)
	}
	key.Version = 2147483647
	tx.state.SigningKeys[key.ID] = key
	if value, err := signer.SignMerkleRoot(t.Context(), request); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, verificationapp.SigningResult{}) {
		t.Fatal("exhausted local version generated a key", err)
	}
}

func TestMemoryMerkleVerificationReadsCurrentDetachedPublicSnapshot(t *testing.T) {
	tx, _, _ := memoryPackageSigningFixture(t)
	r, ok := tx.Repositories().Verification.(verificationapp.MerkleVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks focused Merkle reader")
	}
	tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", FromSequence: 1, ToSequence: 1, EntryCount: 1, LeafHashes: []string{"leaf"}, RootHash: "root", SignatureRefs: []string{"signature"}, CreatedAt: fixedNow()}
	tx.state.AuditEntries["tenant"] = []domain.AuditChainEntry{{TenantID: "tenant", Sequence: 1, EntryHash: "leaf", SubjectID: "private-ignored"}}
	tx.state.Signatures["signature"] = domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", KeyID: "key", Algorithm: "Ed25519", Value: "recorded"}
	subject, err := r.ResolveMerkleVerificationSubject(t.Context(), "tenant", "batch")
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.ReadMerkleVerification(t.Context(), subject)
	if err != nil || v.Subject != subject || len(v.Leaves) != 1 || v.Leaves[0].EntryHash != "leaf" || len(v.Keys) != 1 || len(v.Signatures) != 1 {
		t.Fatal("Merkle snapshot lost owned public facts", err)
	}
	v.Batch.LeafHashes[0] = "changed"
	v.Batch.SignatureRefs[0] = "changed"
	if tx.state.MerkleBatches["batch"].LeafHashes[0] != "leaf" || tx.state.MerkleBatches["batch"].SignatureRefs[0] != "signature" {
		t.Fatal("Merkle snapshot aliases stored arrays")
	}
	if _, err := r.ResolveMerkleVerificationSubject(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing batch resolved", err)
	}
	tx.state.MerkleBatches["foreign"] = domain.MerkleBatch{ID: "foreign", TenantID: "foreign"}
	if value, err := r.ResolveMerkleVerificationSubject(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) || value != (verificationapp.SubjectReference{}) {
		t.Fatal("foreign batch resolved or returned identity", err)
	}
	stored := tx.state.MerkleBatches["batch"]
	stored.RootHash = strings.Repeat("x", 1025)
	tx.state.MerkleBatches[stored.ID] = stored
	if value, err := r.ReadMerkleVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, verificationapp.MerkleVerificationSnapshot{}) {
		t.Fatal("oversized Merkle batch returned partial public facts", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := r.ReadMerkleVerification(ctx, subject); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, verificationapp.MerkleVerificationSnapshot{}) {
		t.Fatal("cancelled Merkle snapshot returned public facts", err)
	}
}

func TestMemoryMerkleVerificationMalformedRangeStillReachesRecordedInspection(t *testing.T) {
	for _, limits := range [][2]int64{{0, 0}, {2, 1}, {-1, 1}} {
		t.Run(fmt.Sprintf("range-%d-%d", limits[0], limits[1]), func(t *testing.T) {
			tx, _, _ := memoryPackageSigningFixture(t)
			r := tx.Repositories().Verification.(verificationapp.MerkleVerificationReader)
			tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", FromSequence: limits[0], ToSequence: limits[1], RootHash: "recorded-root", LeafHashes: []string{}, SignatureRefs: []string{}}
			subject, err := r.ResolveMerkleVerificationSubject(t.Context(), "tenant", "batch")
			if err != nil {
				t.Fatal(err)
			}
			value, err := r.ReadMerkleVerification(t.Context(), subject)
			if err != nil || value.Subject != subject || value.Batch.FromSequence != limits[0] || value.Batch.ToSequence != limits[1] || len(value.Leaves) != 0 {
				t.Fatal("invalid stored range aborted instead of reaching failed receipt inspection", err)
			}
		})
	}
}

func TestMemoryMerkleSigningUsesCurrentLocalKeyAndRejectsMalformedPrivateMaterial(t *testing.T) {
	tx, _, _ := memoryPackageSigningFixture(t)
	signer, ok := tx.Repositories().Signatures.(memoryMerkleSigner)
	if !ok {
		t.Fatal("memory signatures lack focused Merkle signer")
	}
	external := tx.state.SigningKeys["key"]
	external.ID, external.Provider, external.Version = "external", "aws_kms", 999
	tx.state.SigningKeys[external.ID] = external
	request := verificationapp.SigningRequest{TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", Payload: []byte("recorded-root"), CreatedAt: fixedNow()}
	got, err := signer.SignMerkleRoot(t.Context(), request)
	if err != nil || got.NewKey != nil || got.Signature.KeyID != "key" || got.Signature.SubjectID != "batch" {
		t.Fatal("Merkle signing used foreign provider or lost binding", err)
	}
	sig, err := base64.RawStdEncoding.Strict().DecodeString(got.Signature.Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(tx.state.SigningKeys["key"].Private[ed25519.SeedSize:]), request.Payload, sig) {
		t.Fatal("Merkle signature does not verify exact root", err)
	}
	k := tx.state.SigningKeys["key"]
	k.Private = append([]byte(nil), k.Private...)
	k.Private[0] ^= 1
	tx.state.SigningKeys[k.ID] = k
	if v, err := signer.SignMerkleRoot(t.Context(), request); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.SigningResult{}) {
		t.Fatal("malformed private seed/public suffix signed", err)
	}
}
