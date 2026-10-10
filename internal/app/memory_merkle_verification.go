package app

import (
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.MerkleVerificationReader = memoryVerificationRepository{}

func memoryMerkleSubject(s *MemoryUnitOfWorkSnapshot, tenant, id string) (verificationapp.SubjectReference, error) {
	v, ok := s.MerkleBatches[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return verificationapp.SubjectReference{}, ErrNotFound
	}
	return verificationapp.SubjectReference{TenantID: tenant, Type: "merkle_batch", ID: id}, nil
}
func (r memoryVerificationRepository) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return verificationapp.SubjectReference{}, ErrValidation
	}
	var out verificationapp.SubjectReference
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryMerkleSubject(s, tenant, id)
		return err
	})
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return out, nil
}
func (r memoryVerificationRepository) ReadMerkleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	var out verificationapp.MerkleVerificationSnapshot
	if subject.Type != "merkle_batch" || subject.Resources != (application.ResourceReferences{}) || !memoryMembershipQueryText(subject.ID, 1024) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, subject.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		current, err := memoryMerkleSubject(s, subject.TenantID, subject.ID)
		if err != nil {
			return err
		}
		if current != subject {
			return ErrConflict
		}
		b := s.MerkleBatches[subject.ID]
		if len(b.LeafHashes) > verificationapp.MaxMerkleVerificationLeaves || len(b.SignatureRefs) > verificationapp.MaxBundleVerificationSignatures || b.FromSequence > 0 && b.ToSequence >= b.FromSequence && b.ToSequence-b.FromSequence >= verificationapp.MaxMerkleVerificationLeaves {
			return ErrConflict
		}
		for _, v := range append([]string{b.ID, b.TenantID, b.RootHash}, b.LeafHashes...) {
			if !memoryGovernanceText(v, 1024) {
				return ErrConflict
			}
		}
		for _, v := range b.SignatureRefs {
			if !memoryGovernanceText(v, 1024) {
				return ErrConflict
			}
		}
		if !memoryGovernanceText(b.SchemaVersion, 64) {
			return ErrConflict
		}
		budget := memoryCustomerSnapshotBudget{remainingBytes: verificationapp.MaxBundleVerificationBytes}
		raw, err := json.Marshal(b)
		if err != nil {
			return ErrConflict
		}
		if err := budget.chargeJSON(raw); err != nil {
			return err
		}
		cloned, err := cloneMemoryJSON(b)
		if err != nil {
			return ErrConflict
		}
		var leaves []verificationapp.AuditChainLeaf
		if b.FromSequence > 0 && b.ToSequence >= b.FromSequence {
			leaves, err = memoryMerkleLeaves(ctx, s, subject.TenantID, b.FromSequence, b.ToSequence)
			if err != nil {
				return err
			}
		}
		raw, err = json.Marshal(leaves)
		if err != nil {
			return ErrConflict
		}
		if err := budget.chargeJSON(raw); err != nil {
			return err
		}
		var material memoryVerificationPublicMaterial
		if err := readMemoryVerificationPublicMaterial(ctx, s, subject.TenantID, b.SignatureRefs, &budget, &material); err != nil {
			return err
		}
		out = verificationapp.MerkleVerificationSnapshot{Subject: subject, Batch: verificationdomain.MerkleBatch(cloned), Leaves: leaves, Signatures: material.Signatures, Keys: material.Keys}
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.MerkleVerificationSnapshot{}, err
	}
	return out, nil
}
