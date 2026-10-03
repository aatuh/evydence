package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.SBOMPointReader = (*Store)(nil)

// GetSBOMPoint reads one parsed document only when its source evidence and
// optional release/artifact resolve inside the same tenant snapshot.
func (s *Store) GetSBOMPoint(ctx context.Context, tenantID, id string) (evidencequery.SBOMPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return evidencequery.SBOMPoint{}, evidencequery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.SBOMPoint{}, evidencequery.ErrNotFound
	}
	var point evidencequery.SBOMPoint
	var releaseID, artifactID, productID sql.NullString
	var componentsJSON []byte
	sbom := &point.SBOM
	err := s.pool.QueryRow(ctx, `
		SELECT s.id, s.tenant_id, s.evidence_id, s.release_id, s.artifact_id,
		       s.format, s.spec_version, s.component_count, s.components, s.created_at,
		       r.product_id
		FROM sboms AS s
		JOIN evidence_items AS source ON source.id = s.evidence_id AND source.tenant_id = s.tenant_id
		LEFT JOIN releases AS r ON r.id = s.release_id AND r.tenant_id = s.tenant_id
		LEFT JOIN products AS rp ON rp.id = r.product_id AND rp.tenant_id = s.tenant_id
		LEFT JOIN artifacts AS a ON a.id = s.artifact_id AND a.tenant_id = s.tenant_id
		LEFT JOIN products AS ep ON ep.id = source.product_id AND ep.tenant_id = s.tenant_id
		LEFT JOIN projects AS ej ON ej.id = source.project_id AND ej.tenant_id = s.tenant_id
		LEFT JOIN build_runs AS eb ON eb.id = source.build_id AND eb.tenant_id = s.tenant_id
		LEFT JOIN projects AS ebj ON ebj.id = eb.project_id AND ebj.tenant_id = s.tenant_id
		LEFT JOIN releases AS ebr ON ebr.id = eb.release_id AND ebr.tenant_id = s.tenant_id
		LEFT JOIN deployment_events AS ed ON ed.id = source.deployment_id AND ed.tenant_id = s.tenant_id
		LEFT JOIN deployment_environments AS ede ON ede.id = ed.environment_id AND ede.tenant_id = s.tenant_id
		LEFT JOIN releases AS edr ON edr.id = ed.release_id AND edr.tenant_id = s.tenant_id
		LEFT JOIN LATERAL (
		    SELECT COUNT(DISTINCT ref.value->>'id') FILTER (WHERE ref.value->>'type' = 'artifact' AND ref.value->>'id' <> '') AS count
		    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(source.subject_refs) = 'array' THEN source.subject_refs ELSE '[]'::jsonb END) AS ref(value)
		) AS source_artifacts ON true
		WHERE s.tenant_id = $1 AND s.id = $2 AND source.type = 'sbom'
		  AND (s.release_id IS NULL OR rp.id IS NOT NULL)
		  AND (s.artifact_id IS NULL OR a.id IS NOT NULL)
		  AND (s.artifact_id IS NULL AND source_artifacts.count = 0 OR
		       s.artifact_id IS NOT NULL AND source_artifacts.count = 1 AND
		       source.subject_refs @> jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', s.artifact_id)))
		  AND (source.product_id IS NULL OR ep.id IS NOT NULL)
		  AND (source.project_id IS NULL OR ej.id IS NOT NULL)
		  AND (source.product_id IS NULL OR source.project_id IS NULL OR source.product_id = ej.product_id)
		  AND source.release_id IS NOT DISTINCT FROM s.release_id
		  AND (source.product_id IS NULL OR s.release_id IS NULL OR source.product_id = r.product_id)
		  AND (source.project_id IS NULL OR s.release_id IS NULL OR ej.product_id = r.product_id)
		  AND (source.build_id IS NULL OR ebj.id IS NOT NULL AND ebr.id IS NOT NULL AND ebj.product_id = ebr.product_id)
		  AND (source.build_id IS NULL OR s.release_id IS NULL OR eb.release_id = s.release_id)
		  AND (source.deployment_id IS NULL OR ede.id IS NOT NULL AND edr.id IS NOT NULL AND ede.product_id = edr.product_id)
		  AND (source.deployment_id IS NULL OR s.release_id IS NULL OR ed.release_id = s.release_id)
		  AND (source.build_id IS NULL OR source.project_id IS NULL OR source.project_id = eb.project_id)
		  AND (source.build_id IS NULL OR source.release_id IS NULL OR source.release_id = eb.release_id)
		  AND (source.deployment_id IS NULL OR source.release_id IS NULL OR source.release_id = ed.release_id)
		  AND (source.build_id IS NULL OR source.deployment_id IS NULL OR eb.release_id = ed.release_id)`, tenantID, id).Scan(
		&sbom.ID, &sbom.TenantID, &sbom.EvidenceID, &releaseID, &artifactID,
		&sbom.Format, &sbom.SpecVersion, &sbom.ComponentCount, &componentsJSON,
		&sbom.CreatedAt, &productID)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.SBOMPoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.SBOMPoint{}, fmt.Errorf("get SBOM point: %w", err)
	}
	sbom.ReleaseID = nullableSQLString(releaseID)
	sbom.ArtifactID = nullableSQLString(artifactID)
	point.ProductID = nullableSQLString(productID)
	var components []domain.SBOMComponent
	if err := json.Unmarshal(componentsJSON, &components); err != nil || components == nil && (sbom.ComponentCount != 0 || string(componentsJSON) != "null") {
		return evidencequery.SBOMPoint{}, evidencequery.ErrConflict
	}
	sbom.Components = make([]evidencedomain.SBOMComponent, 0, len(components))
	for _, component := range components {
		sbom.Components = append(sbom.Components, evidencedomain.SBOMComponent{
			Identity: component.Identity, Name: component.Name,
			Version: component.Version, PURL: component.PURL,
		})
	}
	return point, nil
}
