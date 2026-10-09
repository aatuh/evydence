package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

var _ evidenceapp.SBOMDiffReader = evidence{}

// ReadSBOMDiffSubject transfers identifiers only. Source evidence parents and
// parsed release/artifact coordinates must agree before components are read.
func (r evidence) ReadSBOMDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	var empty evidenceapp.SBOMDiffSubject
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return empty, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	v := evidenceapp.SBOMDiffSubject{ID: id, TenantID: tenant}
	var refs application.ResourceReferences
	var artifact string
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(s.evidence_id,1025),left(COALESCE(e.product_id,''),1025),left(COALESCE(e.project_id,''),1025),left(COALESCE(e.release_id,''),1025),left(COALESCE(e.build_id,''),1025),left(COALESCE(e.deployment_id,''),1025),left(COALESCE(s.artifact_id,''),1025),
 EXISTS(SELECT 1 FROM unnest(ARRAY[s.evidence_id,e.product_id,e.project_id,e.release_id,e.build_id,e.deployment_id,s.artifact_id]) x(id) WHERE octet_length(x.id)>1024)
 FROM sboms s JOIN evidence_items e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.type='sbom'
 LEFT JOIN artifacts a ON a.id=s.artifact_id AND a.tenant_id=s.tenant_id
 WHERE s.tenant_id=$1 AND s.id=$2 AND s.release_id IS NOT DISTINCT FROM e.release_id
 AND (s.artifact_id IS NULL OR a.id IS NOT NULL)
 AND (s.artifact_id IS NULL AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) x(ref) WHERE x.ref->>'type'='artifact' AND COALESCE(x.ref->>'id','')<>'')
 OR s.artifact_id IS NOT NULL AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type','artifact','id',s.artifact_id)) AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) x(ref) WHERE x.ref->>'type'='artifact' AND COALESCE(x.ref->>'id','')<>'' AND x.ref->>'id'<>s.artifact_id))
 FOR SHARE OF s,e`, tenant, id).Scan(&v.EvidenceID, &refs.ProductID, &refs.ProjectID, &refs.ReleaseID, &refs.BuildID, &refs.DeploymentID, &artifact, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read SBOM diff coordinates: %w", err)
	}
	if large {
		return empty, app.ErrValidation
	}
	resolved, err := r.ResolveEvidenceCreationScope(ctx, tenant, refs)
	if err != nil {
		return empty, err
	}
	// A source build can resolve a release for ownership validation, but must
	// not turn an absent parsed-SBOM release into an accepted diff release.
	v.Resources = application.ResourceReferences{ProductID: resolved.ProductID, ProjectID: resolved.ProjectID, ReleaseID: refs.ReleaseID, ArtifactID: artifact}
	return v, nil
}

func (r evidence) ReadSBOMDiffComponents(ctx context.Context, tenant, id string) ([]evidencedomain.SBOMComponent, error) {
	if _, err := r.ReadSBOMDiffSubject(ctx, tenant, id); err != nil {
		return nil, err
	}
	var raw []byte
	var invalid bool
	// Invalid documents are flagged, not transferred or silently truncated. The
	// count/byte predicate executes before component JSON leaves PostgreSQL.
	err := r.tx.QueryRow(ctx, `WITH selected AS(SELECT components,component_count,
 CASE WHEN jsonb_typeof(components)='array' THEN jsonb_array_length(components) WHEN components='null'::jsonb THEN 0 ELSE -1 END AS actual
 FROM sboms WHERE tenant_id=$1 AND id=$2)
 SELECT CASE WHEN actual BETWEEN 0 AND $3 AND component_count=actual AND octet_length(components::text)<=$4 THEN components ELSE '[]'::jsonb END,
 actual<0 OR actual>$3 OR component_count<>actual OR octet_length(components::text)>$4 FROM selected`, tenant, id, evidenceapp.SBOMDiffComponentLimit, evidenceapp.SBOMDiffProjectionByteLimit).Scan(&raw, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read bounded SBOM diff components: %w", err)
	}
	if invalid {
		return nil, app.ErrValidation
	}
	var components []domain.SBOMComponent
	if json.Unmarshal(raw, &components) != nil {
		return nil, app.ErrValidation
	}
	result := make([]evidencedomain.SBOMComponent, 0, len(components))
	for _, c := range components {
		result = append(result, evidencedomain.SBOMComponent{Identity: c.Identity, Name: c.Name, Version: c.Version, PURL: c.PURL})
	}
	return result, nil
}
