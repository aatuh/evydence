package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r integrity) LockMerkleCreationView(ctx context.Context, tenant string) (verificationapp.MerkleCreationView, error) {
	v := verificationapp.MerkleCreationView{TenantID: tenant}
	_, err := verificationapp.NormalizeSigningKeyID(tenant)
	if ctx == nil || r.tx == nil || err != nil || strings.TrimSpace(tenant) != tenant {
		return v, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return v, err
	}
	// Match every native writer: common fence, tenant root, chain lock, leaves
	// and signing key. Tenant-first would invert the projection lock order.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return v, fmt.Errorf("lock Merkle creation projection: %w", err)
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant); err != nil {
		return v, err
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenant); err != nil {
		return v, fmt.Errorf("lock Merkle creation chain: %w", err)
	}
	// Match Go's strings.TrimSpace, including non-ASCII Unicode whitespace;
	// PostgreSQL's locale-dependent POSIX space class is not equivalent.
	err = r.tx.QueryRow(ctx, `SELECT count(*),coalesce(min(sequence),0),coalesce(max(sequence),0),coalesce(bool_or(btrim(entry_hash,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')=''),false) FROM audit_chain_entries WHERE tenant_id=$1`, tenant).Scan(&v.EntryCount, &v.FirstSequence, &v.LastSequence, &v.HasEmptyHash)
	return v, err
}
func (r integrity) ReadMerkleCreationLeaves(ctx context.Context, tenant string, from, to int64) ([]verificationapp.AuditChainLeaf, error) {
	if from < 1 || to < from || to-from >= verificationapp.MaxMerkleVerificationLeaves {
		return nil, app.ErrValidation
	}
	rows, err := r.tx.Query(ctx, `SELECT sequence,left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 AND sequence BETWEEN $2 AND $3 ORDER BY sequence LIMIT $4 FOR SHARE`, tenant, from, to, verificationapp.MaxMerkleVerificationLeaves+1)
	if err != nil {
		return nil, fmt.Errorf("read Merkle creation leaves: %w", err)
	}
	defer rows.Close()
	var leaves []verificationapp.AuditChainLeaf
	bytes := 0
	for rows.Next() {
		var leaf verificationapp.AuditChainLeaf
		var oversized bool
		if err := rows.Scan(&leaf.Sequence, &leaf.EntryHash, &oversized); err != nil {
			return nil, err
		}
		if oversized || len(leaves) == verificationapp.MaxMerkleVerificationLeaves {
			return nil, app.ErrConflict
		}
		encoded, err := json.Marshal(leaf)
		if err != nil {
			return nil, err
		}
		bytes += len(encoded) + 1
		if bytes > verificationapp.MaxBundleVerificationBytes-2 {
			return nil, app.ErrConflict
		}
		leaves = append(leaves, leaf)
	}
	return leaves, rows.Err()
}
