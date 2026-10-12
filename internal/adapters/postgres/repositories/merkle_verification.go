package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r verification) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return verificationapp.SubjectReference{}, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id); err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return verificationapp.SubjectReference{TenantID: tenant, Type: "merkle_batch", ID: id}, nil
}

// ReadMerkleVerification is called after tenant-wide authorization. It locks
// only the selected batch, covered hashes and referenced public key records.
// Audit canonical bodies/metadata and private signing ciphertext are omitted.
func (r verification) ReadMerkleVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	snapshot := verificationapp.MerkleVerificationSnapshot{Subject: s}
	if s.Type != "merkle_batch" || s.Resources != (application.ResourceReferences{}) {
		return snapshot, app.ErrValidation
	}
	b := &snapshot.Batch
	b.ID, b.TenantID = s.ID, s.TenantID
	var leaves, refs []byte
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT from_sequence,to_sequence,entry_count,
		CASE WHEN cardinality(leaf_hashes)<=$3 AND octet_length(array_to_json(leaf_hashes)::text)<=$4 THEN array_to_json(leaf_hashes) ELSE NULL END,
		left(root_hash,1025),
		CASE WHEN cardinality(signature_refs)<=$5 AND octet_length(array_to_json(signature_refs)::text)<=$4 THEN array_to_json(signature_refs) ELSE NULL END,
		octet_length(root_hash)>1024
		FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, s.ID, verificationapp.MaxMerkleVerificationLeaves, verificationapp.MaxBundleVerificationBytes, verificationapp.MaxBundleVerificationSignatures).Scan(&b.FromSequence, &b.ToSequence, &b.EntryCount, &leaves, &b.RootHash, &refs, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read verification Merkle batch: %w", err)
	}
	bytes := len(leaves) + len(refs) + len(b.RootHash)
	if oversized || len(leaves) == 0 || len(refs) == 0 || bytes > verificationapp.MaxBundleVerificationBytes || b.FromSequence > 0 && b.ToSequence >= b.FromSequence && b.ToSequence-b.FromSequence >= verificationapp.MaxMerkleVerificationLeaves {
		return snapshot, app.ErrConflict
	}
	if err := json.Unmarshal(leaves, &b.LeafHashes); err != nil || b.LeafHashes == nil {
		return snapshot, app.ErrConflict
	}
	if err := json.Unmarshal(refs, &b.SignatureRefs); err != nil || b.SignatureRefs == nil {
		return snapshot, app.ErrConflict
	}
	for _, hash := range b.LeafHashes {
		if len(hash) > 1024 {
			return snapshot, app.ErrConflict
		}
	}
	if b.FromSequence > 0 && b.ToSequence >= b.FromSequence {
		rows, err := r.tx.Query(ctx, `SELECT sequence,left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 AND sequence BETWEEN $2 AND $3 ORDER BY sequence LIMIT $4 FOR SHARE`, s.TenantID, b.FromSequence, b.ToSequence, verificationapp.MaxMerkleVerificationLeaves+1)
		if err != nil {
			return snapshot, fmt.Errorf("read covered verification hashes: %w", err)
		}
		for rows.Next() {
			var leaf verificationapp.AuditChainLeaf
			if err := rows.Scan(&leaf.Sequence, &leaf.EntryHash, &oversized); err != nil {
				rows.Close()
				return snapshot, err
			}
			bytes += len(leaf.EntryHash)
			if oversized || bytes > verificationapp.MaxBundleVerificationBytes || len(snapshot.Leaves) == verificationapp.MaxMerkleVerificationLeaves {
				rows.Close()
				return snapshot, app.ErrConflict
			}
			snapshot.Leaves = append(snapshot.Leaves, leaf)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return snapshot, fmt.Errorf("iterate covered verification hashes: %w", err)
		}
	}
	material, err := r.readVerificationSigningMaterial(ctx, s, b.SignatureRefs, bytes)
	snapshot.Signatures, snapshot.Keys = material.Signatures, material.Keys
	return snapshot, err
}
