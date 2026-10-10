package app

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var (
	_ verificationapp.MerkleCreationReader              = memoryIntegrityRepository{}
	_ verificationapp.TransparencyCheckpointReader      = memoryIntegrityRepository{}
	_ verificationapp.TransparencyCheckpointScopeLocker = memoryIntegrityRepository{}
)

// Current typed fixture views project only sequence/hash and batch identity/root
// fields. This is not SQL locking, bounded transfer or external publication proof.
func (r memoryIntegrityRepository) LockMerkleCreationView(ctx context.Context, tenant string) (verificationapp.MerkleCreationView, error) {
	var out verificationapp.MerkleCreationView
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v := verificationapp.MerkleCreationView{TenantID: tenant}
		for _, entry := range s.AuditEntries[tenant] {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.TenantID != tenant {
				continue
			}
			if v.EntryCount == 0 || entry.Sequence < v.FirstSequence {
				v.FirstSequence = entry.Sequence
			}
			if v.EntryCount == 0 || entry.Sequence > v.LastSequence {
				v.LastSequence = entry.Sequence
			}
			v.EntryCount++
			v.HasEmptyHash = v.HasEmptyHash || strings.TrimSpace(entry.EntryHash) == ""
		}
		out = v
		return nil
	})
	if err != nil {
		return verificationapp.MerkleCreationView{}, err
	}
	return out, nil
}

func (r memoryIntegrityRepository) ReadMerkleCreationLeaves(ctx context.Context, tenant string, from, to int64) ([]verificationapp.AuditChainLeaf, error) {
	if from < 1 || to < from || to-from >= verificationapp.MaxMerkleVerificationLeaves {
		return nil, ErrValidation
	}
	var out []verificationapp.AuditChainLeaf
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryMerkleLeaves(ctx, s, tenant, from, to)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The caller holds the typed view; composing verification must not reacquire
// the same memory transaction mutex through another repository method.
func memoryMerkleLeaves(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant string, from, to int64) ([]verificationapp.AuditChainLeaf, error) {
	if from < 1 || to < from || to-from >= verificationapp.MaxMerkleVerificationLeaves {
		return nil, ErrValidation
	}
	leaves := make([]verificationapp.AuditChainLeaf, 0)
	budget := verificationapp.MaxBundleVerificationBytes - 2
	for _, entry := range s.AuditEntries[tenant] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.TenantID != tenant || entry.Sequence < from || entry.Sequence > to {
			continue
		}
		if len(leaves) == verificationapp.MaxMerkleVerificationLeaves || !memoryGovernanceText(entry.EntryHash, 1024) {
			return nil, ErrConflict
		}
		v := verificationapp.AuditChainLeaf{Sequence: entry.Sequence, EntryHash: entry.EntryHash}
		encoded, err := json.Marshal(v)
		if err != nil || len(encoded)+1 > budget {
			return nil, ErrConflict
		}
		budget -= len(encoded) + 1
		leaves = append(leaves, v)
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Sequence < leaves[j].Sequence })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return leaves, nil
}

func (r memoryIntegrityRepository) LockTransparencyCheckpointScope(ctx context.Context, tenant, id string) error {
	if !memoryMembershipQueryText(id, 1024) {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.MerkleBatches[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}
func (r memoryIntegrityRepository) ReadTransparencyCheckpointSource(ctx context.Context, tenant, id string) (verificationapp.TransparencyCheckpointSource, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return verificationapp.TransparencyCheckpointSource{}, ErrValidation
	}
	var out verificationapp.TransparencyCheckpointSource
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.MerkleBatches[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.RootHash, 1024) {
			return ErrConflict
		}
		out = verificationapp.TransparencyCheckpointSource{TenantID: tenant, ID: id, RootHash: v.RootHash}
		return nil
	})
	if err != nil {
		return verificationapp.TransparencyCheckpointSource{}, err
	}
	return out, nil
}
