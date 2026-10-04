package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const maxReadinessIDs = 4096

// ReadReleaseReadinessSnapshot reads only facts for one release from one
// repeatable-read view. It does not hydrate the process-wide Ledger.
func (s *Store) ReadReleaseReadinessSnapshot(ctx context.Context, tenantID, releaseID string) (riskapp.ReadinessSnapshot, error) {
	var empty riskapp.ReadinessSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(releaseID) == "" {
		return empty, riskapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin readiness snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	snapshot, err := readReleaseReadinessSnapshotTx(ctx, tx, tenantID, releaseID, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit readiness snapshot: %w", err)
	}
	return snapshot, nil
}

func readReleaseReadinessSnapshotTx(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, now time.Time) (riskapp.ReadinessSnapshot, error) {
	return readReleaseReadinessSnapshotBoundedTx(ctx, tx, tenantID, releaseID, now, packageapp.MaxCustomerPackageManifestBytes)
}

func readReleaseReadinessSnapshotBoundedTx(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, now time.Time, maxBytes int) (riskapp.ReadinessSnapshot, error) {
	var empty riskapp.ReadinessSnapshot
	if ctx == nil || tx == nil || maxBytes < 0 || maxBytes > packageapp.MaxCustomerPackageManifestBytes {
		return empty, riskapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	snapshot := riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: tenantID, ReleaseID: releaseID}
	err := tx.QueryRow(ctx, `SELECT r.product_id FROM releases AS r
		JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND r.id=$2`, tenantID, releaseID).Scan(&snapshot.ProductID)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, riskapp.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("resolve readiness release: %w", err)
	}
	presence, err := readReleasePresenceFacts(ctx, tx, tenantID, releaseID)
	if err != nil {
		return empty, err
	}
	snapshot.HasArtifact, snapshot.HasSBOM, snapshot.HasVulnerabilityScan = presence.HasArtifact, presence.HasSBOM, presence.HasVulnerabilityScan
	snapshot.HasArtifactDigest, snapshot.HasPassedBuild, snapshot.HasVerifiedBuildAttestation = presence.HasArtifactDigest, presence.HasPassedBuild, presence.HasVerifiedBuildAttestation
	snapshot.UnhandledCritical, snapshot.UnhandledHigh, err = readReleaseUnhandledPresence(ctx, tx, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	// IDs are the only decision/exception data returned to policy evaluation.
	remainingIDs := maxReadinessIDs
	remainingBytes := maxBytes
	for _, item := range []struct {
		query string
		ids   *[]string
	}{
		{releaseReadinessScopeCTE + ` SELECT v.id FROM scope s JOIN vulnerability_decision_projection v ON ` + readinessDecisionOwnershipSQL + ` WHERE coalesce(v.superseded_by,'')='' AND v.customer_visible AND btrim(coalesce(v.impact_statement,''))=''`, &snapshot.MissingCustomerStatementIDs},
		{releaseReadinessScopeCTE + ` SELECT v.id FROM scope s JOIN vulnerability_decision_projection v ON ` + readinessDecisionOwnershipSQL + ` WHERE coalesce(v.superseded_by,'')='' AND v.status='not_affected' AND btrim(v.justification)=''`, &snapshot.MissingNotAffectedReasonIDs},
		{releaseReadinessScopeCTE + ` SELECT x.id FROM scope s JOIN exceptions x ON ` + readinessExceptionOwnershipSQL + ` WHERE btrim(x.owner)='' OR btrim(x.reason)='' OR (x.approved AND (btrim(coalesce(x.approved_by,''))='' OR x.approved_at IS NULL))`, &snapshot.IncompleteExceptionIDs},
	} {
		*item.ids, err = readReadinessIDs(ctx, tx, item.query, &remainingIDs, &remainingBytes, tenantID, releaseID)
		if err != nil {
			return empty, err
		}
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM customer_security_packages p WHERE `+readinessCustomerPackageScopeSQL, tenantID, releaseID).Scan(&snapshot.PackageCount)
	if err != nil {
		return empty, fmt.Errorf("read readiness package count: %w", err)
	}
	if snapshot.PackageCount > remainingIDs {
		return empty, riskapp.ErrValidation
	}
	snapshot.InvalidPackageOrProfileIDs, err = readReadinessIDs(ctx, tx, `SELECT p.id FROM customer_security_packages AS p
		LEFT JOIN redaction_profiles AS r ON r.id=p.redaction_profile_id AND r.tenant_id=p.tenant_id
		WHERE `+readinessCustomerPackageScopeSQL+` AND (r.id IS NULL OR cardinality(r.allowed_types)=0 OR p.expires_at<=$3
		OR NOT (ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'] <@ (SELECT coalesce(array_agg(lower(btrim(value))),'{}'::text[]) FROM unnest(r.excluded_fields) AS value)))
		`, &remainingIDs, &remainingBytes, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	verified, err := readVerifiedReadinessBundle(ctx, tx, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	snapshot.HasVerifiedSignedBundle = verified
	return snapshot, nil
}

const readinessCustomerPackageScopeSQL = `p.tenant_id=$1 AND p.release_id=$2
	AND EXISTS(SELECT 1 FROM releases root WHERE root.id=p.release_id AND root.tenant_id=p.tenant_id AND root.product_id=p.product_id)`

// Fixed internal SELECTs supply identifiers only. PostgreSQL checks the whole
// selected list before transferring any identifier; it never truncates an ID
// or collection into a plausible readiness result. Budgets span every list.
func readReadinessIDs(ctx context.Context, tx pgx.Tx, query string, remainingIDs, remainingBytes *int, args ...any) ([]string, error) {
	limitParam, byteParam := len(args)+1, len(args)+2
	args = append(args, *remainingIDs+1, *remainingBytes)
	rows, err := tx.Query(ctx, fmt.Sprintf(`WITH ids AS MATERIALIZED (%s ORDER BY id LIMIT $%d), bounds AS (
	 SELECT count(*) >= $%d OR coalesce(sum(octet_length(to_jsonb(id)::text)),0)>$%d
	 OR coalesce(bool_or(octet_length(id)>1024),false) AS rejected FROM ids
	) SELECT CASE WHEN bounds.rejected THEN '' ELSE ids.id END,bounds.rejected
	FROM ids CROSS JOIN bounds ORDER BY ids.id COLLATE "C"`, query, limitParam, limitParam, byteParam), args...)
	if err != nil {
		return nil, fmt.Errorf("read readiness identifiers: %w", err)
	}
	defer rows.Close()
	var out []string
	used := 0
	for rows.Next() {
		var id string
		var rejected bool
		if err := rows.Scan(&id, &rejected); err != nil {
			return nil, fmt.Errorf("scan readiness identifier: %w", err)
		}
		if rejected || !customerSnapshotID(id, false) || len(out) >= *remainingIDs {
			return nil, riskapp.ErrValidation
		}
		encoded, err := json.Marshal(id)
		if err != nil || len(encoded) > *remainingBytes-used {
			return nil, riskapp.ErrValidation
		}
		used += len(encoded)
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate readiness identifiers: %w", err)
	}
	*remainingIDs -= len(out)
	*remainingBytes -= used
	return out, nil
}

var releaseUnhandledFindingsCTE = releaseReadinessScopeCTE + `, findings AS (
		SELECT d.id AS scan_id, f.value->>'id' AS finding_id, lower(f.value->>'severity') AS severity,
			lower(coalesce(nullif(f.value->>'state',''),'open')) AS state,
			f.value->>'vulnerability' AS vulnerability, f.value->>'component' AS component
		` + releaseReadinessScansFromSQL + `
		CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(d.findings)='array' THEN d.findings ELSE '[]'::jsonb END) AS f(value)
	), unhandled AS (
		SELECT f.* FROM findings AS f
		WHERE f.state='open' AND f.severity IN ('critical','high')
		AND NOT EXISTS (
			SELECT 1 FROM vulnerability_decision_projection AS d
			WHERE d.tenant_id=$1 AND d.finding_id=f.finding_id AND d.scan_id=f.scan_id AND d.release_id=$2 AND coalesce(d.superseded_by,'')=''
			AND d.vulnerability=f.vulnerability AND coalesce(d.component,'')=coalesce(f.component,'')
			AND (SELECT count(*) FROM findings same WHERE same.scan_id=f.scan_id AND same.finding_id=f.finding_id)=1
			AND d.status IN ('fixed','not_affected')
		) AND NOT EXISTS (
			SELECT 1 FROM scope s JOIN exceptions x ON ` + readinessExceptionOwnershipSQL + ` WHERE x.approved AND x.expires_at>$3 AND (coalesce(x.finding_id,'')='' OR x.finding_id=f.finding_id)
		)
	) `

func readVerifiedReadinessBundle(ctx context.Context, tx pgx.Tx, tenantID, releaseID string, now time.Time) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT left(b.manifest_hash,257),left(sg.value,257),left(k.public_key,257),left(k.status,257),k.created_at,k.valid_from,k.valid_until,k.revoked_at,left(k.revocation_semantics,257),left(k.historical_validity_policy,257),k.compromised_at,sg.created_at,
		(octet_length(b.manifest_hash)>256 OR octet_length(sg.value)>256 OR octet_length(k.public_key)>256 OR octet_length(k.status)>256 OR octet_length(k.revocation_semantics)>256 OR octet_length(k.historical_validity_policy)>256)
		FROM release_bundles AS b
		CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(b.signature_refs)='array' THEN b.signature_refs ELSE '[]'::jsonb END) AS ref(value)
		JOIN signatures AS sg ON sg.id=ref.value AND sg.tenant_id=b.tenant_id AND sg.subject_type='release_bundle' AND sg.subject_id=b.id AND sg.algorithm='Ed25519'
		JOIN signing_keys AS k ON k.id=sg.key_id AND k.tenant_id=b.tenant_id AND k.algorithm='Ed25519'
		WHERE b.tenant_id=$1 AND b.release_id=$2 LIMIT 257`, tenantID, releaseID)
	if err != nil {
		return false, fmt.Errorf("read readiness bundle signatures: %w", err)
	}
	defer rows.Close()
	verified, count := false, 0
	for rows.Next() {
		count++
		if count > 256 {
			return false, riskapp.ErrValidation
		}
		var hash, signature, publicKey, status, semantics, policy string
		var keyCreatedAt, signedAt time.Time
		var validFrom, validUntil, revokedAt, compromisedAt *time.Time
		var oversized bool
		if err := rows.Scan(&hash, &signature, &publicKey, &status, &keyCreatedAt, &validFrom, &validUntil, &revokedAt, &semantics, &policy, &compromisedAt, &signedAt, &oversized); err != nil {
			return false, fmt.Errorf("scan readiness signature: %w", err)
		}
		if oversized {
			return false, riskapp.ErrValidation
		}
		keyStatus, err := verificationdomain.ParseSigningKeyStatus(status)
		if err != nil {
			continue
		}
		key := verificationdomain.SigningKey{Status: keyStatus, CreatedAt: keyCreatedAt, ValidUntil: validUntil, RevokedAt: revokedAt, RevocationSemantics: semantics, HistoricalValidityPolicy: policy, CompromisedAt: compromisedAt}
		if validFrom != nil {
			key.ValidFrom = *validFrom
		}
		if key.HistoricalValidityAt(signedAt, now) != verificationdomain.SigningKeyHistoricalValidityValid {
			continue
		}
		pub, pubErr := base64.RawStdEncoding.DecodeString(publicKey)
		sig, sigErr := base64.RawStdEncoding.DecodeString(signature)
		if pubErr == nil && sigErr == nil && len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), []byte(hash), sig) {
			verified = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate readiness signatures: %w", err)
	}
	return verified, nil
}
