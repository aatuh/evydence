package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ packageapp.ReleaseBundleSnapshotReader = (*Store)(nil)

const maxBundleProofBytes = 8 << 20

// ReadReleaseBundleSnapshot selects only the complete manifest inputs, never
// raw payloads, provider locations, credentials, or signing material. All
// queries use one read-only repeatable-read view and fail closed on overflow.
func (s *Store) ReadReleaseBundleSnapshot(ctx context.Context, tenantID, releaseID string, now time.Time) (packageapp.ReleaseBundleSnapshot, error) {
	var empty packageapp.ReleaseBundleSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(releaseID) == "" || now.IsZero() {
		return empty, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin release bundle snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	snapshot, err := readReleaseBundleSnapshotTx(ctx, tx, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit release bundle snapshot: %w", err)
	}
	return snapshot, nil
}

func readReleaseBundleSnapshotTx(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, now time.Time) (packageapp.ReleaseBundleSnapshot, error) {
	var empty packageapp.ReleaseBundleSnapshot
	snapshot := packageapp.ReleaseBundleSnapshot{SnapshotVersion: packageapp.ReleaseBundleSnapshotVersion, TenantID: tenantID, ReleaseID: releaseID, EvidenceIDs: []string{}}
	var oversized bool
	err := tx.QueryRow(ctx, `SELECT left(r.product_id,1025),left(r.version,4097),left(r.state,65),
		(octet_length(r.product_id)>1024 OR octet_length(r.version)>4096 OR octet_length(r.state)>64)
		FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND r.id=$2`, tenantID, releaseID).Scan(&snapshot.ProductID, &snapshot.ReleaseVersion, &snapshot.ReleaseState, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, packageapp.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read release bundle scope: %w", err)
	}
	if oversized || snapshot.ProductID == "" || snapshot.ReleaseVersion == "" || snapshot.ReleaseState == "" {
		return empty, packageapp.ErrConflict
	}
	rows, err := tx.Query(ctx, `SELECT left(id,1025),octet_length(id)>1024 FROM evidence_items WHERE tenant_id=$1 AND release_id=$2 ORDER BY id LIMIT $3`, tenantID, releaseID, packageapp.MaxBundleSnapshotRows+1)
	if err != nil {
		return empty, fmt.Errorf("read release bundle evidence: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id, &oversized); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan release bundle evidence: %w", err)
		}
		if oversized || strings.TrimSpace(id) == "" || len(snapshot.EvidenceIDs) == packageapp.MaxBundleSnapshotRows {
			rows.Close()
			return empty, packageapp.ErrConflict
		}
		snapshot.EvidenceIDs = append(snapshot.EvidenceIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate release bundle evidence: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT sequence,left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&snapshot.ChainSequence, &snapshot.ChainHeadHash, &oversized)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return empty, fmt.Errorf("read release bundle chain head: %w", err)
	}
	if err == nil && (oversized || snapshot.ChainSequence <= 0 || snapshot.ChainHeadHash == "") {
		return empty, packageapp.ErrConflict
	}
	policies, err := readBundleRetentionPolicies(ctx, tx, tenantID, packageapp.MaxBundleSnapshotRows-len(snapshot.EvidenceIDs))
	if err != nil {
		return empty, err
	}
	snapshot.ObjectLockProofs = verificationapp.ObjectLockProofs(policies, now)
	return snapshot, nil
}

func readBundleRetentionPolicies(ctx context.Context, tx pgx.Tx, tenantID string, remaining int) ([]verificationdomain.ObjectRetentionPolicy, error) {
	policies, _, err := readPublicRetentionPoliciesTx(ctx, tx, tenantID, remaining, maxBundleProofBytes)
	return policies, err
}
