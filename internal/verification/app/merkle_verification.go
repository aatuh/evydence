package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxMerkleVerificationLeaves = 4096

// MerkleVerificationSnapshot contains only one batch, its covered sequence
// hashes and referenced public signing material, never raw audit payloads.
type MerkleVerificationSnapshot struct {
	Subject    SubjectReference
	Batch      verificationdomain.MerkleBatch
	Leaves     []AuditChainLeaf
	Signatures []verificationdomain.Signature
	Keys       []verificationdomain.SigningKey
}
type MerkleVerificationReader interface {
	ResolveMerkleVerificationSubject(context.Context, string, string) (SubjectReference, error)
	ReadMerkleVerification(context.Context, SubjectReference) (MerkleVerificationSnapshot, error)
}
type MerkleVerificationTransaction interface {
	MerkleVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type MerkleVerificationTransactions interface {
	ExecuteMerkleVerification(context.Context, func(context.Context, MerkleVerificationTransaction) error) error
}
type MerkleVerificationConfig struct {
	Transactions MerkleVerificationTransactions
	Authorizer   application.Authorizer
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type MerkleVerificationCommands struct{ config MerkleVerificationConfig }

func NewMerkleVerificationCommands(config MerkleVerificationConfig) (*MerkleVerificationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Verifier == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &MerkleVerificationCommands{config}, nil
}

func (s *MerkleVerificationCommands) VerifyMerkleBatch(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	id = strings.TrimSpace(id)
	if !validSigningKeyText(id) || len(id) > 1024 {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	var result verificationdomain.VerificationResult
	err := s.config.Transactions.ExecuteMerkleVerification(ctx, func(ctx context.Context, tx MerkleVerificationTransaction) error {
		subject, err := tx.ResolveMerkleVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "merkle_batch", id) || subject.Resources != (application.ResourceReferences{}) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		snapshot, err := tx.ReadMerkleVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		inspection, err := InspectMerkleBatch(snapshot, now, s.config.Verifier)
		if err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, inspection, now, s.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}

// InspectMerkleBatch evaluates the recorded hashes only. It does not rehash
// canonical audit contents or assert external transparency-log inclusion.
func InspectMerkleBatch(s MerkleVerificationSnapshot, now time.Time, verifier PayloadSignatureVerifier) (SubjectInspection, error) {
	b := s.Batch
	if verifier == nil || now.IsZero() || !validSubjectReference(s.Subject, b.TenantID, "merkle_batch", b.ID) || b.ID == "" || b.TenantID == "" || len(s.Leaves) > MaxMerkleVerificationLeaves || len(b.LeafHashes) > MaxMerkleVerificationLeaves || len(b.SignatureRefs) > MaxBundleVerificationSignatures || len(s.Signatures) > MaxBundleVerificationSignatures || len(s.Keys) > MaxBundleVerificationSignatures || b.FromSequence > 0 && b.ToSequence >= b.FromSequence && b.ToSequence-b.FromSequence >= MaxMerkleVerificationLeaves {
		return SubjectInspection{}, ErrConflict
	}
	if !merkleVerificationWithinBudget(s) {
		return SubjectInspection{}, ErrConflict
	}
	coverage, root, signature := "failed", "failed", "failed"
	if b.FromSequence > 0 && b.ToSequence >= b.FromSequence && int64(len(s.Leaves)) == b.ToSequence-b.FromSequence+1 && b.EntryCount == len(s.Leaves) && len(b.LeafHashes) == len(s.Leaves) {
		coverage = "passed"
		for i, leaf := range s.Leaves {
			if leaf.Sequence != b.FromSequence+int64(i) || leaf.EntryHash != b.LeafHashes[i] {
				coverage = "failed"
				break
			}
		}
	}
	if merkleRoot(b.LeafHashes) == b.RootHash {
		root = "passed"
	}
	if validReferencedPayloadSignature(s.Subject, b.SignatureRefs, s.Signatures, s.Keys, []byte(b.RootHash), now, verifier) {
		signature = "passed"
	}
	return SubjectInspection{Checks: []verificationdomain.VerifyCheck{{Name: "checkpoint_coverage", Result: coverage}, {Name: "merkle_root", Result: root}, {Name: "checkpoint_signature", Result: signature}}, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileMerkleCheckpoint, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: []string{"checkpoint_coverage", "merkle_root", "checkpoint_signature"}, TrustMaterial: []string{"tenant signing keys"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "Merkle batch leaf hashes and signed root", PayloadDigest: b.RootHash, Limitations: []string{"Merkle checkpoint verification does not establish external transparency-log inclusion."}})}, nil
}

func merkleVerificationWithinBudget(s MerkleVerificationSnapshot) bool {
	bytes := 0
	consume := func(text string, limit int) bool {
		if len(text) > limit || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return false
		}
		bytes += len(text)
		return bytes <= MaxBundleVerificationBytes
	}
	for _, text := range []string{s.Batch.ID, s.Batch.TenantID, s.Batch.RootHash} {
		if !consume(text, 1024) {
			return false
		}
	}
	for _, text := range s.Batch.LeafHashes {
		if !consume(text, 1024) {
			return false
		}
	}
	for _, text := range s.Batch.SignatureRefs {
		if !consume(text, 1024) {
			return false
		}
	}
	for _, leaf := range s.Leaves {
		if !consume(leaf.EntryHash, 1024) {
			return false
		}
	}
	for _, sig := range s.Signatures {
		for _, text := range []string{sig.ID, sig.TenantID, sig.SubjectID, sig.KeyID} {
			if !consume(text, 1024) {
				return false
			}
		}
		if !consume(sig.SubjectType, 64) || !consume(sig.Algorithm, 64) || !consume(sig.Value, 16384) {
			return false
		}
	}
	for _, key := range s.Keys {
		if !consume(key.ID, 1024) || !consume(key.TenantID, 1024) || !consume(key.Algorithm, 64) || !consume(key.PublicKey, 16384) || !consume(key.Status.String(), 64) || !consume(key.RevocationSemantics, 64) || !consume(key.HistoricalValidityPolicy, 64) {
			return false
		}
	}
	return true
}
