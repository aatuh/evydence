package postgres

import (
	"context"
	"encoding/json"
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
	// Check the total selected metadata before transferring variable-sized JSON
	// or arrays. Repeatable read keeps the budget and rows in the same view.
	var count, bytes, detailRows int64
	var malformed bool
	err := tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(
		octet_length(id)+octet_length(name)+octet_length(mode)+octet_length(status)+
		octet_length(coalesce(verification_hash,''))+octet_length(verification_provider)+octet_length(verification_mode)+
		octet_length(verification_checks::text)+octet_length(verification_limitations::text)),0),
		coalesce(sum(CASE WHEN jsonb_typeof(verification_checks)='array' THEN jsonb_array_length(verification_checks) ELSE 0 END + cardinality(verification_limitations)),0),
		coalesce(bool_or(jsonb_typeof(verification_checks) IS DISTINCT FROM 'array' OR array_position(verification_limitations,NULL) IS NOT NULL),false)
		FROM object_retention_policies WHERE tenant_id=$1`, tenantID).Scan(&count, &bytes, &detailRows, &malformed)
	if err != nil {
		return nil, fmt.Errorf("read bundle retention budget: %w", err)
	}
	if count > int64(remaining) || bytes > maxBundleProofBytes || detailRows > packageapp.MaxBundleSnapshotRows || malformed {
		return nil, packageapp.ErrConflict
	}
	rows, err := tx.Query(ctx, `SELECT left(id,1025),left(name,4097),object_prefix<>'',coalesce(object_key,'')<>'',require_legal_hold,
		left(mode,65),retention_days,left(status,65),left(coalesce(verification_hash,''),1025),
		left(verification_provider,65),left(verification_mode,65),verification_retention_days,verification_checks,verification_limitations,
		created_at,verified_at,verification_observed_at,verification_expires_at,verification_legal_hold,
		(octet_length(id)>1024 OR octet_length(name)>4096 OR octet_length(mode)>64 OR octet_length(status)>64 OR
		 octet_length(coalesce(verification_hash,''))>1024 OR octet_length(verification_provider)>64 OR octet_length(verification_mode)>64)
		FROM object_retention_policies WHERE tenant_id=$1 ORDER BY id LIMIT $2`, tenantID, remaining+1)
	if err != nil {
		return nil, fmt.Errorf("read bundle retention facts: %w", err)
	}
	defer rows.Close()
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0, int(count))
	for rows.Next() {
		var policy verificationdomain.ObjectRetentionPolicy
		var prefix, objectKey, oversized bool
		var checks []byte
		err := rows.Scan(&policy.ID, &policy.Name, &prefix, &objectKey, &policy.RequireLegalHold,
			&policy.Mode, &policy.RetentionDays, &policy.Status, &policy.VerificationHash,
			&policy.VerificationProvider, &policy.VerificationMode, &policy.VerificationRetentionDays, &checks, &policy.VerificationLimitations,
			&policy.CreatedAt, &policy.VerifiedAt, &policy.VerificationObservedAt, &policy.VerificationExpiresAt, &policy.VerificationLegalHold, &oversized)
		if err != nil {
			return nil, fmt.Errorf("scan bundle retention facts: %w", err)
		}
		if oversized || len(policies) == remaining || policy.ID == "" || len(checks) == 0 || checks[0] != '[' {
			return nil, packageapp.ErrConflict
		}
		if err := json.Unmarshal(checks, &policy.VerificationChecks); err != nil {
			return nil, packageapp.ErrConflict
		}
		policy.TenantID = tenantID
		// These are presence markers, not provider locations. No raw location
		// crosses the repository boundary into a manifest renderer.
		if prefix {
			policy.ObjectPrefix = "configured"
		}
		if objectKey {
			policy.ObjectKey = "configured"
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate bundle retention facts: %w", err)
	}
	return policies, nil
}
