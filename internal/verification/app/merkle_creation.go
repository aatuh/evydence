package app

import (
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type MerkleCreationView struct {
	TenantID                                string
	EntryCount, FirstSequence, LastSequence int64
	HasEmptyHash                            bool
}
type MerkleCreationReader interface {
	LockMerkleCreationView(context.Context, string) (MerkleCreationView, error)
	ReadMerkleCreationLeaves(context.Context, string, int64, int64) ([]AuditChainLeaf, error)
}
type MerkleCreationTransaction interface {
	MerkleCreationReader
	application.Authorizer
	application.AuditAppender
	SignMerkleRoot(context.Context, SigningRequest) (SigningResult, error)
	InsertSigningKey(context.Context, PreparedSigningKey) error
	InsertSignature(context.Context, verificationdomain.Signature) error
	InsertMerkleBatch(context.Context, verificationdomain.MerkleBatch) error
}
type MerkleCreationTransactions interface {
	ExecuteMerkleCreation(context.Context, func(context.Context, MerkleCreationTransaction) error) error
}
type MerkleCreationConfig struct {
	Transactions MerkleCreationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type MerkleCreationCommands struct{ config MerkleCreationConfig }

func NewMerkleCreationCommands(c MerkleCreationConfig) (*MerkleCreationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &MerkleCreationCommands{c}, nil
}

// ValidateMerkleCreationInput checks only request shape. Zero bounds retain
// their historical meaning and are resolved only against a fresh locked view.
func ValidateMerkleCreationInput(in CreateMerkleBatchInput) error {
	if in.FromSequence < 0 || in.ToSequence < 0 || in.ToSequence != 0 && in.FromSequence > in.ToSequence {
		return ErrValidation
	}
	return nil
}

// AuthorizeMerkleCreation is a current tenant-admin replay guard. Native
// transactions retain the tenant fence/root lock through the outer commit;
// the guard never reads chain leaves or signing keys, generates IDs or signs.
func (s *MerkleCreationCommands) AuthorizeMerkleCreation(ctx context.Context, a identitydomain.Actor) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateSigningKeyActor(a); err != nil {
		return err
	}
	r := application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}
	if err := s.config.Authorizer.Authorize(ctx, a, r); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteMerkleCreation(ctx, func(ctx context.Context, tx MerkleCreationTransaction) error { return tx.Authorize(ctx, a, r) })
}
func (s *MerkleCreationCommands) CreateMerkleBatch(ctx context.Context, a identitydomain.Actor, in CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	if err := validateSigningKeyActor(a); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	request := application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}
	if err := s.config.Authorizer.Authorize(ctx, a, request); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	if err := ValidateMerkleCreationInput(in); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	var result verificationdomain.MerkleBatch
	err := s.config.Transactions.ExecuteMerkleCreation(ctx, func(ctx context.Context, tx MerkleCreationTransaction) error {
		if err := tx.Authorize(ctx, a, request); err != nil {
			return err
		}
		view, err := tx.LockMerkleCreationView(ctx, a.TenantID)
		if err != nil {
			return err
		}
		if view.TenantID != a.TenantID {
			return ErrNotFound
		}
		if view.EntryCount < 1 || view.FirstSequence != 1 || view.LastSequence != view.EntryCount || view.HasEmptyHash {
			return ErrValidation
		}
		from, to := in.FromSequence, in.ToSequence
		if from == 0 {
			from = 1
		}
		if to == 0 {
			to = view.LastSequence
		}
		if from < 1 || to < from || to > view.LastSequence {
			return ErrValidation
		}
		if to-from >= MaxMerkleVerificationLeaves {
			return ErrConflict
		}
		leaves, err := tx.ReadMerkleCreationLeaves(ctx, a.TenantID, from, to)
		if err != nil {
			return err
		}
		if int64(len(leaves)) != to-from+1 {
			return ErrValidation
		}
		hashes := make([]string, len(leaves))
		for i, leaf := range leaves {
			if leaf.Sequence != from+int64(i) || !validSigningKeyText(leaf.EntryHash) {
				return ErrValidation
			}
			if len(leaf.EntryHash) > 1024 {
				return ErrConflict
			}
			hashes[i] = leaf.EntryHash
		}
		encoded, err := json.Marshal(leaves)
		if err != nil {
			return err
		}
		if len(encoded) > MaxBundleVerificationBytes {
			return ErrConflict
		}
		root := merkleRoot(hashes)
		now := s.config.Clock.Now().UTC()
		id := s.config.IDs.NewID("mb")
		raw, err := tx.SignMerkleRoot(ctx, SigningRequest{TenantID: a.TenantID, SubjectType: "merkle_batch", SubjectID: id, Payload: []byte(root), CreatedAt: now})
		if err != nil {
			clearSigningResult(&raw)
			return err
		}
		signing := cloneSigningResult(raw)
		clearSigningResult(&raw)
		defer clearSigningResult(&signing)
		sig := signing.Signature
		if !validSignature(sig, a.TenantID, "merkle_batch", id, now) {
			return ErrValidation
		}
		if signing.NewKey != nil {
			if !validNewSigningKey(*signing.NewKey, a.TenantID, now) || signing.NewKey.Key.ID != sig.KeyID {
				return ErrValidation
			}
			if err := tx.InsertSigningKey(ctx, *signing.NewKey); err != nil {
				return err
			}
		}
		batch := verificationdomain.MerkleBatch{ID: id, TenantID: a.TenantID, FromSequence: from, ToSequence: to, EntryCount: len(hashes), LeafHashes: hashes, RootHash: root, SignatureRefs: []string{sig.ID}, SchemaVersion: verificationdomain.MerkleBatchSchemaVersion, CreatedAt: now}
		if err := tx.InsertSignature(ctx, sig); err != nil {
			return err
		}
		if err := tx.InsertMerkleBatch(ctx, batch); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "merkle_batch.created", SubjectType: "merkle_batch", SubjectID: id, PayloadHash: root, SignatureRef: sig.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now})
		if err != nil {
			return err
		}
		result = cloneMerkleBatch(batch)
		return nil
	})
	if err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	return result, nil
}
