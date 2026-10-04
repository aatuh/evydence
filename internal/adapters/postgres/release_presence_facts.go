package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type releasePresenceFacts struct {
	HasArtifact, HasSBOM, HasVulnerabilityScan, HasArtifactDigest bool
	HasPassedBuild, HasVerifiedBuildAttestation                   bool
}

// Shared fixed-size SQL projections keep readiness and anomaly trust semantics
// identical without loading raw evidence, report packages or signing keys.
func readReleasePresenceFacts(ctx context.Context, tx pgx.Tx, tenant, release string) (releasePresenceFacts, error) {
	var v releasePresenceFacts
	// Only registered, tenant-owned artifacts can contribute a trusted digest.
	linkedDigests := `SELECT a.digest FROM evidence_items AS e
		CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) AS ref(value)
		JOIN artifacts AS a ON a.id=ref.value->>'id' AND a.tenant_id=e.tenant_id
		WHERE e.tenant_id=$1 AND e.release_id=$2 AND ref.value->>'type'='artifact'
		AND a.digest ~ '^sha256:[0-9a-fA-F]{64}$'`
	err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM evidence_items AS e CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) AS ref(value) WHERE e.tenant_id=$1 AND e.release_id=$2 AND ref.value->>'type'='artifact' AND coalesce(ref.value->>'id','')<>''),
		EXISTS(SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND release_id=$2 AND type='sbom'),
		EXISTS(SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND release_id=$2 AND type='vulnerability_scan'),
		EXISTS(`+linkedDigests+`),
		EXISTS(SELECT 1 FROM build_runs AS b CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END) AS output(value) WHERE b.tenant_id=$1 AND b.release_id=$2 AND b.status='passed' AND output.value->>'digest' IN (`+linkedDigests+`)),
		EXISTS(SELECT 1 FROM build_attestations AS a JOIN build_runs AS b ON b.id=a.build_id AND b.tenant_id=a.tenant_id JOIN verification_results AS v ON v.tenant_id=a.tenant_id AND v.subject_type='build_attestation' AND v.subject_id=a.id AND v.result='passed' AND v.assurance_profile->>'id'=$3 AND v.schema_version=$4 CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(a.subject_digests)='array' THEN a.subject_digests ELSE '[]'::jsonb END) AS digest(value) WHERE a.tenant_id=$1 AND b.release_id=$2 AND digest.value IN (`+linkedDigests+`))`, tenant, release, verificationdomain.VerificationProfileDSSEAttestationSignature, verificationdomain.VerificationResultSchemaVersion).Scan(&v.HasArtifact, &v.HasSBOM, &v.HasVulnerabilityScan, &v.HasArtifactDigest, &v.HasPassedBuild, &v.HasVerifiedBuildAttestation)
	if err != nil {
		return releasePresenceFacts{}, fmt.Errorf("read readiness presence: %w", err)
	}
	return v, nil
}
func readReleaseUnhandledPresence(ctx context.Context, tx pgx.Tx, tenant, release string, now time.Time) (bool, bool, error) {
	var invalidFindings bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability_scans AS s
		WHERE s.tenant_id=$1 AND s.release_id=$2 AND (
			jsonb_typeof(s.findings)<>'array' OR EXISTS(
				SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.findings)='array' THEN s.findings ELSE '[]'::jsonb END) AS f(value)
				WHERE jsonb_typeof(f.value)<>'object' OR btrim(coalesce(f.value->>'id',''))='' OR btrim(coalesce(f.value->>'severity',''))=''
			)
		))`, tenant, release).Scan(&invalidFindings)
	if err != nil {
		return false, false, fmt.Errorf("validate readiness findings: %w", err)
	}
	if invalidFindings {
		return false, false, riskapp.ErrValidation
	}
	var critical, high bool
	err = tx.QueryRow(ctx, releaseUnhandledFindingsCTE+` SELECT coalesce(bool_or(severity='critical'),false),coalesce(bool_or(severity='high'),false) FROM unhandled`, tenant, release, now).Scan(&critical, &high)
	if err != nil {
		return false, false, fmt.Errorf("read readiness findings: %w", err)
	}
	return critical, high, nil
}
