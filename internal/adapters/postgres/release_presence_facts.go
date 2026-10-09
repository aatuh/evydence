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
	// Only coherent sources and registered tenant-owned artifacts contribute
	// digests. No raw source payload or receipt details cross this boundary.
	err := tx.QueryRow(ctx, releaseReadinessScopeCTE+`, evidence AS MATERIALIZED (
		SELECT e.id,e.type,e.subject_refs FROM scope s JOIN evidence_items e ON `+customerCatalogEvidenceScopeSQL+`
	), linked_digests AS MATERIALIZED (
		SELECT a.digest FROM evidence e CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) ref
		JOIN artifacts a ON a.id=ref->>'id' AND a.tenant_id=$1 WHERE ref->>'type'='artifact' AND a.digest ~ '^sha256:[0-9a-fA-F]{64}$'
	), builds AS MATERIALIZED (
		SELECT b.id,b.tenant_id,b.project_id,b.release_id,b.status,b.outputs FROM scope s JOIN build_runs b ON `+customerProvenanceBuildScopeSQL+` AND NOT (`+customerProvenanceOutputsInvalidSQL+`)
	) SELECT
		EXISTS(SELECT 1 FROM evidence e CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) ref WHERE ref->>'type'='artifact' AND coalesce(ref->>'id','')<>''),
		EXISTS(SELECT 1 FROM evidence WHERE type='sbom'),
		EXISTS(SELECT 1 FROM evidence WHERE type='vulnerability_scan'),
		EXISTS(SELECT 1 FROM linked_digests),
		EXISTS(SELECT 1 FROM builds b CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END) output WHERE b.status='passed' AND output->>'digest' IN (SELECT digest FROM linked_digests)),
		EXISTS(SELECT 1 FROM scope s JOIN builds b ON b.tenant_id=s.tenant_id JOIN build_attestations a ON a.build_id=b.id AND a.tenant_id=b.tenant_id
		JOIN evidence_items e ON `+customerProvenanceAttestationSourceSQL+`
		JOIN verification_results v ON v.tenant_id=a.tenant_id AND v.subject_type='build_attestation' AND v.subject_id=a.id AND v.result='passed' AND v.assurance_profile->>'id'=$3 AND v.schema_version=$4
		CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(a.subject_digests)='array' THEN a.subject_digests ELSE '[]'::jsonb END) digest
		WHERE NOT (`+customerSnapshotStringListInvalidSQL("a.subject_digests")+`) AND digest IN (SELECT digest FROM linked_digests))`, tenant, release, verificationdomain.VerificationProfileDSSEAttestationSignature, verificationdomain.VerificationResultSchemaVersion).Scan(&v.HasArtifact, &v.HasSBOM, &v.HasVulnerabilityScan, &v.HasArtifactDigest, &v.HasPassedBuild, &v.HasVerifiedBuildAttestation)
	if err != nil {
		return releasePresenceFacts{}, fmt.Errorf("read readiness presence: %w", err)
	}
	return v, nil
}
func readReleaseUnhandledPresence(ctx context.Context, tx pgx.Tx, tenant, release string, now time.Time) (bool, bool, error) {
	var invalidFindings bool
	err := tx.QueryRow(ctx, releaseReadinessScopeCTE+` SELECT EXISTS(SELECT 1 `+releaseReadinessScansFromSQL+`
		WHERE (
			jsonb_typeof(d.findings)<>'array' OR EXISTS(
				SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.findings)='array' THEN d.findings ELSE '[]'::jsonb END) AS f(value)
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
