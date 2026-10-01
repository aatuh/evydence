package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.EvidenceFlowReader = (*Store)(nil)

// ReadEvidenceFlowSnapshot computes every count in one tenant-bound SQL
// statement, so all categories use the same PostgreSQL statement snapshot.
// No evidence row or tenant-wide collection is materialized in Go.
func (s *Store) ReadEvidenceFlowSnapshot(ctx context.Context, tenantID, releaseID string) (releasequery.EvidenceFlowSnapshot, error) {
	var empty releasequery.EvidenceFlowSnapshot
	if s == nil || s.pool == nil || ctx == nil {
		return empty, releasequery.ErrValidation
	}
	tenantID, releaseID = strings.TrimSpace(tenantID), strings.TrimSpace(releaseID)
	if tenantID == "" || releaseID == "" {
		return empty, releasequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var snapshot releasequery.EvidenceFlowSnapshot
	var artifactRefs, passedBuilds, buildAttestations, sboms, scans int64
	var vexDocuments, decisions, bundles, packages int64
	err := s.pool.QueryRow(ctx, `
		SELECT r.tenant_id, r.id, r.product_id,
		  (SELECT count(*) FROM (
		    SELECT artifact_id AS id FROM sboms WHERE tenant_id = $1 AND release_id = r.id
		    UNION
		    SELECT artifact_id AS id FROM vex_documents WHERE tenant_id = $1 AND release_id = r.id
		    UNION
		    SELECT output.value->>'artifact_id' AS id
		    FROM build_runs AS b
		    CROSS JOIN LATERAL jsonb_array_elements(
		      CASE WHEN jsonb_typeof(b.outputs) = 'array' THEN b.outputs ELSE '[]'::jsonb END
		    ) AS output(value)
		    WHERE b.tenant_id = $1 AND b.release_id = r.id
		  ) AS refs WHERE refs.id IS NOT NULL AND refs.id <> ''),
		  (SELECT count(*) FROM build_runs WHERE tenant_id = $1 AND release_id = r.id AND status = 'passed'),
		  (SELECT count(*) FROM build_attestations AS a
		    JOIN build_runs AS b ON b.id = a.build_id AND b.tenant_id = a.tenant_id
		    WHERE a.tenant_id = $1 AND b.release_id = r.id),
		  (SELECT count(*) FROM sboms WHERE tenant_id = $1 AND release_id = r.id),
		  (SELECT count(*) FROM vulnerability_scans WHERE tenant_id = $1 AND release_id = r.id),
		  (SELECT count(*) FROM vex_documents WHERE tenant_id = $1 AND release_id = r.id),
		  (SELECT count(*) FROM vulnerability_decisions
		    WHERE tenant_id = $1 AND release_id = r.id AND coalesce(superseded_by, '') = ''),
		  (SELECT count(*) FROM release_bundles WHERE tenant_id = $1 AND release_id = r.id),
		  (SELECT count(*) FROM customer_security_packages WHERE tenant_id = $1 AND release_id = r.id)
		FROM releases AS r
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND r.id = $2
	`, tenantID, releaseID).Scan(
		&snapshot.TenantID, &snapshot.ReleaseID, &snapshot.ProductID,
		&artifactRefs, &passedBuilds, &buildAttestations, &sboms, &scans,
		&vexDocuments, &decisions, &bundles, &packages,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, releasequery.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read release evidence flow counts: %w", err)
	}
	snapshot.Counts = map[string]int{
		"artifact_refs": int(artifactRefs), "passed_builds": int(passedBuilds),
		"build_attestations": int(buildAttestations), "sboms": int(sboms),
		"vulnerability_scans": int(scans), "vex_documents": int(vexDocuments),
		"vulnerability_decisions": int(decisions), "release_bundles": int(bundles),
		"customer_packages": int(packages),
	}
	return snapshot, nil
}
