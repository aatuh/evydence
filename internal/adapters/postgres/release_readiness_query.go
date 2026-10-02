package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
	var empty riskapp.ReadinessSnapshot
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
	// Only the linked, registered artifact digest can be used for build and
	// attestation matching. A free-form subject_ref digest is not trusted.
	linkedDigests := `SELECT a.digest FROM evidence_items AS e
		CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) AS ref(value)
		JOIN artifacts AS a ON a.id=ref.value->>'id' AND a.tenant_id=e.tenant_id
		WHERE e.tenant_id=$1 AND e.release_id=$2 AND ref.value->>'type'='artifact'
		AND a.digest ~ '^sha256:[0-9a-fA-F]{64}$'`
	err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM evidence_items AS e CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) AS ref(value) WHERE e.tenant_id=$1 AND e.release_id=$2 AND ref.value->>'type'='artifact' AND coalesce(ref.value->>'id','')<>''),
		EXISTS(SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND release_id=$2 AND type='sbom'),
		EXISTS(SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND release_id=$2 AND type='vulnerability_scan'),
		EXISTS(`+linkedDigests+`),
		EXISTS(SELECT 1 FROM build_runs AS b CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END) AS output(value) WHERE b.tenant_id=$1 AND b.release_id=$2 AND b.status='passed' AND output.value->>'digest' IN (`+linkedDigests+`)),
		EXISTS(SELECT 1 FROM build_attestations AS a JOIN build_runs AS b ON b.id=a.build_id AND b.tenant_id=a.tenant_id JOIN verification_results AS v ON v.tenant_id=a.tenant_id AND v.subject_type='build_attestation' AND v.subject_id=a.id AND v.result='passed' AND v.assurance_profile->>'id'=$3 AND v.schema_version=$4 CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(a.subject_digests)='array' THEN a.subject_digests ELSE '[]'::jsonb END) AS digest(value) WHERE a.tenant_id=$1 AND b.release_id=$2 AND digest.value IN (`+linkedDigests+`))`,
		tenantID, releaseID, verificationdomain.VerificationProfileDSSEAttestationSignature, verificationdomain.VerificationResultSchemaVersion,
	).Scan(&snapshot.HasArtifact, &snapshot.HasSBOM, &snapshot.HasVulnerabilityScan, &snapshot.HasArtifactDigest, &snapshot.HasPassedBuild, &snapshot.HasVerifiedBuildAttestation)
	if err != nil {
		return empty, fmt.Errorf("read readiness presence: %w", err)
	}
	var invalidFindings bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability_scans AS s
		WHERE s.tenant_id=$1 AND s.release_id=$2 AND (
			jsonb_typeof(s.findings)<>'array' OR EXISTS(
				SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.findings)='array' THEN s.findings ELSE '[]'::jsonb END) AS f(value)
				WHERE jsonb_typeof(f.value)<>'object' OR btrim(coalesce(f.value->>'id',''))='' OR btrim(coalesce(f.value->>'severity',''))=''
			)
		))`, tenantID, releaseID).Scan(&invalidFindings)
	if err != nil {
		return empty, fmt.Errorf("validate readiness findings: %w", err)
	}
	if invalidFindings {
		return empty, riskapp.ErrValidation
	}
	// A current decision or a scoped approved exception handles a finding.
	// This is an existence projection; scanner payload bytes never leave SQL.
	err = tx.QueryRow(ctx, releaseUnhandledFindingsCTE+` SELECT coalesce(bool_or(severity='critical'),false),coalesce(bool_or(severity='high'),false) FROM unhandled`, tenantID, releaseID, now).Scan(&snapshot.UnhandledCritical, &snapshot.UnhandledHigh)
	if err != nil {
		return empty, fmt.Errorf("read readiness findings: %w", err)
	}
	// IDs are the only decision/exception data returned to policy evaluation.
	remainingIDs := maxReadinessIDs
	for _, item := range []struct {
		query string
		ids   *[]string
	}{
		{`SELECT left(id,1025) FROM vulnerability_decision_projection WHERE tenant_id=$1 AND release_id=$2 AND coalesce(superseded_by,'')='' AND customer_visible AND btrim(coalesce(impact_statement,''))='' ORDER BY id LIMIT $3`, &snapshot.MissingCustomerStatementIDs},
		{`SELECT left(id,1025) FROM vulnerability_decision_projection WHERE tenant_id=$1 AND release_id=$2 AND coalesce(superseded_by,'')='' AND status='not_affected' AND btrim(justification)='' ORDER BY id LIMIT $3`, &snapshot.MissingNotAffectedReasonIDs},
		{`SELECT left(id,1025) FROM exceptions WHERE tenant_id=$1 AND release_id=$2 AND (btrim(owner)='' OR btrim(reason)='' OR (approved AND (btrim(coalesce(approved_by,''))='' OR approved_at IS NULL))) ORDER BY id LIMIT $3`, &snapshot.IncompleteExceptionIDs},
	} {
		rows, err := tx.Query(ctx, item.query, tenantID, releaseID, remainingIDs+1)
		if err != nil {
			return empty, fmt.Errorf("read readiness exceptions and decisions: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return empty, fmt.Errorf("scan readiness identifier: %w", err)
			}
			if len(id) > 1024 || remainingIDs == 0 {
				rows.Close()
				return empty, riskapp.ErrValidation
			}
			*item.ids = append(*item.ids, id)
			remainingIDs--
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return empty, fmt.Errorf("iterate readiness identifiers: %w", err)
		}
		rows.Close()
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM customer_security_packages WHERE tenant_id=$1 AND release_id=$2`, tenantID, releaseID).Scan(&snapshot.PackageCount)
	if err != nil || snapshot.PackageCount > remainingIDs {
		return empty, riskapp.ErrValidation
	}
	rows, err := tx.Query(ctx, `SELECT p.id FROM customer_security_packages AS p
		LEFT JOIN redaction_profiles AS r ON r.id=p.redaction_profile_id AND r.tenant_id=p.tenant_id
		WHERE p.tenant_id=$1 AND p.release_id=$2 AND (r.id IS NULL OR cardinality(r.allowed_types)=0 OR p.expires_at<=$3
		OR NOT (ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'] <@ (SELECT coalesce(array_agg(lower(btrim(value))),'{}'::text[]) FROM unnest(r.excluded_fields) AS value)))
		ORDER BY p.id LIMIT $4`, tenantID, releaseID, now, remainingIDs+1)
	if err != nil {
		return empty, fmt.Errorf("read readiness package profiles: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan readiness package: %w", err)
		}
		if len(id) > 1024 || len(snapshot.InvalidPackageOrProfileIDs) >= remainingIDs {
			rows.Close()
			return empty, riskapp.ErrValidation
		}
		snapshot.InvalidPackageOrProfileIDs = append(snapshot.InvalidPackageOrProfileIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return empty, fmt.Errorf("iterate readiness packages: %w", err)
	}
	rows.Close()
	verified, err := readVerifiedReadinessBundle(ctx, tx, tenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	snapshot.HasVerifiedSignedBundle = verified
	return snapshot, nil
}

const releaseUnhandledFindingsCTE = `WITH findings AS (
		SELECT s.id AS scan_id, f.value->>'id' AS finding_id, lower(f.value->>'severity') AS severity,
			lower(coalesce(nullif(f.value->>'state',''),'open')) AS state,
			f.value->>'vulnerability' AS vulnerability, f.value->>'component' AS component
		FROM vulnerability_scans AS s
		CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(s.findings)='array' THEN s.findings ELSE '[]'::jsonb END) AS f(value)
		WHERE s.tenant_id=$1 AND s.release_id=$2
	), unhandled AS (
		SELECT f.* FROM findings AS f
		WHERE f.state='open' AND f.severity IN ('critical','high')
		AND NOT EXISTS (
			SELECT 1 FROM vulnerability_decision_projection AS d
			WHERE d.tenant_id=$1 AND d.finding_id=f.finding_id AND coalesce(d.superseded_by,'')=''
			AND d.id=(SELECT latest.id FROM vulnerability_decision_projection AS latest WHERE latest.tenant_id=$1 AND latest.finding_id=f.finding_id AND coalesce(latest.superseded_by,'')='' ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1)
			AND d.status IN ('fixed','not_affected')
		) AND NOT EXISTS (
			SELECT 1 FROM exceptions AS x WHERE x.tenant_id=$1 AND x.release_id=$2 AND x.approved AND x.expires_at>$3 AND (coalesce(x.finding_id,'')='' OR x.finding_id=f.finding_id)
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
