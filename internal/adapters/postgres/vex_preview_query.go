package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ evidencequery.VEXPreviewReader = (*Store)(nil)

type vexPreviewArtifactReader struct{ tx pgx.Tx }

func (r vexPreviewArtifactReader) GetArtifactPoint(ctx context.Context, in releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return repositories.ReadArtifactGrant(ctx, r.tx, in)
}

// ReadVEXPreviewSnapshot selects only finding coordinates and active-decision
// presence. It never reads decision text, evidence metadata, or object bytes.
func (s *Store) ReadVEXPreviewSnapshot(ctx context.Context, tenant, release, artifact string, prepare evidencequery.VEXPreviewPreparation) (evidencequery.VEXPreviewSnapshot, error) {
	if prepare == nil {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrValidation
	}
	tx, err := s.beginVEXPointSnapshot(ctx, tenant, release)
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, err
	}
	defer rollbackVEXPointSnapshot(ctx, tx)
	release, artifact = strings.TrimSpace(release), strings.TrimSpace(artifact)
	out := evidencequery.VEXPreviewSnapshot{TenantID: tenant, ReleaseID: release, ArtifactID: artifact}
	var oversized bool
	err = tx.QueryRow(ctx, `SELECT left(r.product_id,1025),octet_length(r.product_id)>1024 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2`, tenant, release).Scan(&out.ProductID, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("resolve VEX preview release: %w", err)
	}
	if oversized {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrConflict
	}
	if artifact != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM artifacts WHERE tenant_id=$1 AND id=$2)`, tenant, artifact).Scan(&exists); err != nil {
			return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("resolve VEX preview artifact: %w", err)
		}
		if !exists {
			return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrNotFound
		}
	}
	auth, err := releasequery.NewArtifactReadAuthorizer(vexPreviewArtifactReader{tx})
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, err
	}
	ids, err := prepare(application.ResourceReferences{ProductID: out.ProductID, ReleaseID: release}, auth)
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, err
	}
	if len(ids) == 0 {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrConflict
	}
	var scanCount int
	var malformed, orphan bool
	err = tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_or(jsonb_typeof(s.findings) NOT IN('array','null')),false),
 coalesce(bool_or(e.id IS NULL OR e.type<>'vulnerability_scan' OR e.release_id IS DISTINCT FROM s.release_id
 OR(e.product_id IS NOT NULL AND e.product_id<>$3)OR(e.project_id IS NOT NULL AND(j.id IS NULL OR j.product_id<>$3))),false)
 FROM vulnerability_scans s LEFT JOIN evidence_items e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id
 LEFT JOIN projects j ON j.id=e.project_id AND j.tenant_id=e.tenant_id WHERE s.tenant_id=$1 AND s.release_id=$2`, tenant, release, out.ProductID).Scan(&scanCount, &malformed, &orphan)
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("validate VEX preview scans: %w", err)
	}
	if orphan {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrNotFound
	}
	if malformed || scanCount > evidencequery.MaxVEXPreviewScans {
		return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrConflict
	}
	rows, err := tx.Query(ctx, `SELECT left(coalesce(f.value->>'id',''),1025),left(s.id,1025),left(f.value->>'vulnerability',1048577),left(coalesce(f.value->>'component',''),1048577),
 EXISTS(SELECT 1 FROM vulnerability_decision_projection d WHERE d.tenant_id=s.tenant_id AND d.finding_id=f.value->>'id' AND coalesce(d.superseded_by,'')=''),
 jsonb_typeof(f.value) IS DISTINCT FROM 'object' OR jsonb_typeof(f.value->'id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(f.value->'vulnerability') IS DISTINCT FROM 'string' OR coalesce(jsonb_typeof(f.value->'component') NOT IN('string','null'),false)
 OR octet_length(f.value->>'id')>1024 OR octet_length(s.id)>1024 OR octet_length(f.value->>'vulnerability')>1048576 OR octet_length(coalesce(f.value->>'component',''))>1048576
 OR EXISTS(SELECT 1 FROM vulnerability_decision_projection d WHERE d.tenant_id=s.tenant_id AND d.finding_id=f.value->>'id' AND coalesce(d.superseded_by,'')='' AND(d.scan_id<>s.id OR(d.release_id IS NOT NULL AND d.release_id<>s.release_id)))
 FROM vulnerability_scans s CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(s.findings)='array' THEN s.findings ELSE '[]'::jsonb END)f(value)
 WHERE s.tenant_id=$1 AND s.release_id=$2 AND f.value->>'vulnerability'=ANY($3::text[])
 ORDER BY s.id,f.value->>'id' LIMIT $4`, tenant, release, ids, evidencequery.MaxVEXPreviewFindings+1)
	if err != nil {
		return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("read VEX preview candidates: %w", err)
	}
	defer rows.Close()
	budget := evidencequery.MaxVEXPreviewTextBytes
	for rows.Next() {
		var f evidencequery.VEXPreviewFinding
		var invalid bool
		f.TenantID, f.ReleaseID = tenant, release
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Vulnerability, &f.Component, &f.HasActiveDecision, &invalid); err != nil {
			return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("scan VEX preview candidate: %w", err)
		}
		if invalid || len(out.Findings) >= evidencequery.MaxVEXPreviewFindings {
			return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrConflict
		}
		for _, text := range []string{f.ID, f.ScanID, f.TenantID, f.ReleaseID, f.Vulnerability, f.Component} {
			if len(text) > budget {
				return evidencequery.VEXPreviewSnapshot{}, evidencequery.ErrConflict
			}
			budget -= len(text)
		}
		out.Findings = append(out.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return evidencequery.VEXPreviewSnapshot{}, fmt.Errorf("iterate VEX preview candidates: %w", err)
	}
	return out, nil
}
