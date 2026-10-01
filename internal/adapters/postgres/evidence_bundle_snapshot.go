package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ packageapp.EvidenceBundleSnapshotReader = (*Store)(nil)

// ReadEvidenceBundleSnapshot reads IDs, validated scope coordinates, the chain
// head and bounded public retention proof metadata from one committed view.
func (s *Store) ReadEvidenceBundleSnapshot(ctx context.Context, tenantID, releaseID string, now time.Time) (packageapp.EvidenceBundleSnapshot, error) {
	var empty packageapp.EvidenceBundleSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || now.IsZero() {
		return empty, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin evidence bundle snapshot: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	snapshot, err := readEvidenceBundleSnapshotTx(ctx, tx, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit evidence bundle snapshot: %w", err)
	}
	return snapshot, nil
}

func readEvidenceBundleSnapshotTx(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, now time.Time) (packageapp.EvidenceBundleSnapshot, error) {
	var empty packageapp.EvidenceBundleSnapshot
	snapshot := packageapp.EvidenceBundleSnapshot{SnapshotVersion: packageapp.EvidenceBundleSnapshotVersion, TenantID: tenantID, ReleaseID: releaseID, Evidence: []packageapp.EvidenceBundleEvidence{}}
	var oversized bool
	if releaseID != "" {
		err := tx.QueryRow(ctx, `SELECT left(r.product_id,1025),octet_length(r.product_id)>1024 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2`, tenantID, releaseID).Scan(&snapshot.ProductID, &oversized)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, packageapp.ErrNotFound
		}
		if err != nil {
			return empty, fmt.Errorf("read export release scope: %w", err)
		}
		if oversized || snapshot.ProductID == "" {
			return empty, packageapp.ErrConflict
		}
	} else {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenantID).Scan(&exists); err != nil {
			return empty, fmt.Errorf("read export tenant: %w", err)
		}
		if !exists {
			return empty, packageapp.ErrNotFound
		}
	}
	rows, err := tx.Query(ctx, `SELECT left(id,1025),octet_length(id)>1024 FROM evidence_items WHERE tenant_id=$1 AND ($2='' OR release_id=$2) ORDER BY id LIMIT $3`, tenantID, releaseID, packageapp.MaxBundleSnapshotRows+1)
	if err != nil {
		return empty, fmt.Errorf("read export evidence IDs: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id, &oversized); err != nil {
			rows.Close()
			return empty, err
		}
		if oversized || strings.TrimSpace(id) == "" || len(ids) == packageapp.MaxBundleSnapshotRows {
			rows.Close()
			return empty, packageapp.ErrConflict
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate export evidence: %w", err)
	}
	// Budget proof rows before reading the evidence coordinates so an overflow
	// fails early; every query is still in this same repeatable-read view.
	policies, err := readBundleRetentionPolicies(ctx, tx, tenantID, packageapp.MaxBundleSnapshotRows-len(ids))
	if err != nil {
		return empty, err
	}
	for _, id := range ids {
		raw, err := repositories.ReadEvidenceBundleCoordinates(ctx, tx, tenantID, id, false)
		if err != nil {
			if errors.Is(err, app.ErrConflict) || errors.Is(err, app.ErrNotFound) {
				return empty, packageapp.ErrConflict
			}
			return empty, err
		}
		refs, err := repositories.ResolveEvidenceBundleCoordinates(ctx, tx, tenantID, raw)
		if err != nil {
			if errors.Is(err, app.ErrConflict) || errors.Is(err, evidencequery.ErrNotFound) {
				return empty, packageapp.ErrConflict
			}
			return empty, err
		}
		snapshot.Evidence = append(snapshot.Evidence, packageapp.EvidenceBundleEvidence{ID: id, Resources: refs})
	}
	err = tx.QueryRow(ctx, `SELECT left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&snapshot.AuditChainHead, &oversized)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return empty, fmt.Errorf("read export chain head: %w", err)
	}
	if err == nil && (oversized || snapshot.AuditChainHead == "") {
		return empty, packageapp.ErrConflict
	}
	snapshot.ObjectLockProofs = verificationapp.ObjectLockProofs(policies, now)
	return snapshot, nil
}
