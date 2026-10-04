package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type AuditChainLeaf struct {
	Sequence  int64
	EntryHash string
}

type SigningRequest struct {
	TenantID    string
	SubjectType string
	SubjectID   string
	Payload     []byte
	CreatedAt   time.Time
}

type SigningResult struct {
	Signature verificationdomain.Signature
	NewKey    *PreparedSigningKey
}

type CreateMerkleBatchInput struct {
	FromSequence int64
	ToSequence   int64
}

func (s *Service) CreateMerkleBatch(ctx context.Context, actor identitydomain.Actor, input CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	if err := s.authorize(ctx, actor, ScopeKeysAdmin, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	leaves, err := s.integrity.ReadAuditChain(ctx, actor.TenantID)
	if err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	leaves = append([]AuditChainLeaf(nil), leaves...)
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Sequence < leaves[j].Sequence })
	if !validAuditChainLeaves(leaves) {
		return verificationdomain.MerkleBatch{}, ErrValidation
	}
	from, to := input.FromSequence, input.ToSequence
	if from == 0 {
		from = 1
	}
	if to == 0 {
		to = leaves[len(leaves)-1].Sequence
	}
	if from < 1 || to < from {
		return verificationdomain.MerkleBatch{}, ErrValidation
	}
	hashes := make([]string, 0, to-from+1)
	for _, leaf := range leaves {
		if leaf.Sequence >= from && leaf.Sequence <= to {
			hashes = append(hashes, leaf.EntryHash)
		}
	}
	if int64(len(hashes)) != to-from+1 {
		return verificationdomain.MerkleBatch{}, ErrValidation
	}
	root := merkleRoot(hashes)
	now := s.clock.Now().UTC()
	batchID := s.ids.NewID("mb")
	signing, err := s.signer.Sign(ctx, SigningRequest{TenantID: actor.TenantID, SubjectType: "merkle_batch", SubjectID: batchID, Payload: []byte(root), CreatedAt: now})
	if err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	rawSigning := signing
	signing = cloneSigningResult(rawSigning)
	clearSigningResult(&rawSigning)
	defer clearSigningResult(&signing)
	signature := signing.Signature
	if !validSignature(signature, actor.TenantID, "merkle_batch", batchID, now) {
		return verificationdomain.MerkleBatch{}, ErrValidation
	}
	if signing.NewKey != nil && (!validNewSigningKey(*signing.NewKey, actor.TenantID, now) || signing.NewKey.Key.ID != signature.KeyID) {
		return verificationdomain.MerkleBatch{}, ErrValidation
	}
	batch := verificationdomain.MerkleBatch{
		ID: batchID, TenantID: actor.TenantID, FromSequence: from, ToSequence: to, EntryCount: len(hashes),
		LeafHashes: append([]string(nil), hashes...), RootHash: root, SignatureRefs: []string{signature.ID},
		SchemaVersion: verificationdomain.MerkleBatchSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		if signing.NewKey != nil {
			if err := tx.Verification().InsertSigningKey(ctx, *signing.NewKey); err != nil {
				return err
			}
		}
		if err := tx.Verification().InsertSignature(ctx, signature); err != nil {
			return err
		}
		if err := tx.Verification().InsertMerkleBatch(ctx, batch); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "merkle_batch.created", "merkle_batch", batch.ID)
		audit.PayloadHash = root
		audit.SignatureRef = signature.ID
		_, err := tx.Audit().AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	return cloneMerkleBatch(batch), nil
}

type CreateTransparencyCheckpointInput struct {
	BatchID     string
	Provider    string
	ExternalURL string
	ExternalID  string
}

func (s *Service) CreateTransparencyCheckpoint(ctx context.Context, actor identitydomain.Actor, input CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	if err := s.authorize(ctx, actor, ScopeKeysAdmin, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	input, err := NormalizeTransparencyCheckpointInput(input)
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	batch, err := s.integrity.ReadMerkleBatch(ctx, actor.TenantID, input.BatchID)
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	now := s.clock.Now().UTC()
	checkpoint, err := recordedTransparencyCheckpoint(actor.TenantID, input, TransparencyCheckpointSource{TenantID: batch.TenantID, ID: batch.ID, RootHash: batch.RootHash}, s.canonicalHasher, now, s.ids.NewID("tcp"))
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.Verification().InsertTransparencyCheckpoint(ctx, checkpoint); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "transparency_checkpoint.recorded", "transparency_checkpoint", checkpoint.ID)
		audit.PayloadHash = checkpoint.TimestampHash
		_, err := tx.Audit().AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	return checkpoint, nil
}

func validAuditChainLeaves(leaves []AuditChainLeaf) bool {
	if len(leaves) == 0 {
		return false
	}
	for index, leaf := range leaves {
		if leaf.Sequence != int64(index+1) || strings.TrimSpace(leaf.EntryHash) == "" {
			return false
		}
	}
	return true
}

func validSignature(signature verificationdomain.Signature, tenantID, subjectType, subjectID string, now time.Time) bool {
	return signature.ID != "" && signature.TenantID == tenantID && signature.SubjectType == subjectType && signature.SubjectID == subjectID && signature.KeyID != "" && signature.Algorithm != "" && signature.Value != "" && !signature.CreatedAt.IsZero() && !signature.CreatedAt.After(now)
}

func validNewSigningKey(prepared PreparedSigningKey, tenantID string, now time.Time) bool {
	key := prepared.Key
	return key.ID != "" && key.TenantID == tenantID && key.KID != "" && key.Version > 0 && key.Provider == verificationdomain.SigningKeyDefaultProvider && key.Algorithm == "Ed25519" && key.Status.String() == verificationdomain.SigningKeyStatusActive && key.PublicKey != "" && key.PublicKeyFingerprint != "" && !key.ValidFrom.After(now) && !key.CreatedAt.After(now) && len(prepared.PrivateMaterial) > 0
}

func cloneSigningResult(value SigningResult) SigningResult {
	if value.NewKey != nil {
		copy := clonePreparedSigningKey(*value.NewKey)
		value.NewKey = &copy
	}
	return value
}

func clearSigningResult(value *SigningResult) {
	if value != nil && value.NewKey != nil {
		clear(value.NewKey.PrivateMaterial)
	}
}

func merkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			right := level[index]
			if index+1 < len(level) {
				right = level[index+1]
			}
			digest := sha256.Sum256([]byte(level[index] + "\n" + right))
			next = append(next, "sha256:"+hex.EncodeToString(digest[:]))
		}
		level = next
	}
	return level[0]
}

func cloneMerkleBatch(value verificationdomain.MerkleBatch) verificationdomain.MerkleBatch {
	value.LeafHashes = append([]string(nil), value.LeafHashes...)
	value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
	return value
}
