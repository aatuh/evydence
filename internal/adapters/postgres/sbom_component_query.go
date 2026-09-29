package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.SBOMComponentReader = (*Store)(nil)

// PageSBOMComponents applies current tenant ownership and resource grants in
// PostgreSQL before keyset pagination; only a bounded page leaves the store.
func (s *Store) PageSBOMComponents(ctx context.Context, request evidencequery.SBOMComponentPageRequest) (appquery.Result[evidencequery.SBOMComponentPoint], error) {
	var empty appquery.Result[evidencequery.SBOMComponentPoint]
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedProjectIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedProjectIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return empty, evidencequery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil || request.Page.Sort != appquery.SortID || request.After != nil && request.After.Value != request.After.ID {
		return empty, evidencequery.ErrValidation
	}
	filter := request.Filter
	filter.SBOMID = strings.TrimSpace(filter.SBOMID)
	filter.ReleaseID = strings.TrimSpace(filter.ReleaseID)
	filter.ArtifactID = strings.TrimSpace(filter.ArtifactID)
	filter.Query = strings.ToLower(strings.TrimSpace(filter.Query))
	filter.PURL = strings.TrimSpace(filter.PURL)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin SBOM component snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	cursorID := ""
	if request.After != nil {
		cursorID = request.After.ID
	}
	comparison, direction := ">", "ASC"
	if request.Page.Direction == appquery.Descending {
		comparison, direction = "<", "DESC"
	}
	visibilitySQL := `
		WITH valid_sboms AS (
		    SELECT s.id, s.tenant_id, s.release_id, s.artifact_id, s.format,
		           s.spec_version, s.components, sr.product_id AS release_product_id,
		           a.digest AS artifact_digest
		    FROM sboms AS s
		    JOIN evidence_items AS source ON source.id = s.evidence_id AND source.tenant_id = s.tenant_id
		    LEFT JOIN releases AS sr ON sr.id = s.release_id AND sr.tenant_id = s.tenant_id
		    LEFT JOIN products AS rp ON rp.id = sr.product_id AND rp.tenant_id = s.tenant_id
		    LEFT JOIN artifacts AS a ON a.id = s.artifact_id AND a.tenant_id = s.tenant_id
		    LEFT JOIN products AS source_product ON source_product.id = source.product_id AND source_product.tenant_id = s.tenant_id
		    LEFT JOIN projects AS source_project ON source_project.id = source.project_id AND source_project.tenant_id = s.tenant_id
		    WHERE s.tenant_id = $1
		      AND (s.release_id IS NULL OR sr.id IS NOT NULL AND rp.id IS NOT NULL)
		      AND (s.artifact_id IS NULL OR a.id IS NOT NULL)
		      AND (source.product_id IS NULL OR source_product.id IS NOT NULL)
		      AND (source.project_id IS NULL OR source_project.id IS NOT NULL)
		      AND (source.product_id IS NULL OR source.project_id IS NULL OR source.product_id = source_project.product_id)
		      AND (source.release_id IS NULL OR source.release_id = s.release_id)
		      AND (source.product_id IS NULL OR s.release_id IS NULL OR source.product_id = sr.product_id)
		      AND (source.project_id IS NULL OR s.release_id IS NULL OR source_project.product_id = sr.product_id)
		      AND ($6 = '' OR s.id = $6)
		      AND ($7 = '' OR s.release_id = $7)
		      AND ($8 = '' OR s.artifact_id = $8)
		), visible_sboms AS (
		    SELECT s.*, visible.product_id, visible.project_id, visible.release_id AS visible_release_id
		    FROM valid_sboms AS s
		    JOIN LATERAL (
		        SELECT s.release_product_id AS product_id, NULL::text AS project_id,
		               s.release_id AS release_id
		        WHERE $2
		        UNION ALL
		        SELECT s.release_product_id, NULL::text, s.release_id
		        WHERE NOT $2 AND s.release_id = ANY($5::text[])
		        UNION ALL
		        SELECT s.release_product_id, NULL::text, s.release_id
		        WHERE NOT $2 AND s.artifact_id IS NULL AND s.release_product_id = ANY($3::text[])
		        UNION ALL
		        SELECT e.product_id, e.project_id, e.release_id
		        FROM evidence_items AS e
		        LEFT JOIN products AS ep ON ep.id = e.product_id AND ep.tenant_id = e.tenant_id
		        LEFT JOIN projects AS ej ON ej.id = e.project_id AND ej.tenant_id = e.tenant_id
		        LEFT JOIN releases AS er ON er.id = e.release_id AND er.tenant_id = e.tenant_id
		        WHERE NOT $2 AND s.artifact_id IS NOT NULL AND e.tenant_id = s.tenant_id
		          AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', s.artifact_id))
		          AND (e.product_id IS NULL OR ep.id IS NOT NULL)
		          AND (e.project_id IS NULL OR ej.id IS NOT NULL)
		          AND (e.release_id IS NULL OR er.id IS NOT NULL)
		          AND (e.product_id IS NULL OR e.project_id IS NULL OR e.product_id = ej.product_id)
		          AND (e.product_id IS NULL OR e.release_id IS NULL OR e.product_id = er.product_id)
		          AND (e.project_id IS NULL OR e.release_id IS NULL OR ej.product_id = er.product_id)
		          AND (e.product_id = ANY($3::text[]) AND (s.release_id IS NULL OR e.product_id = s.release_product_id)
		               OR e.project_id = ANY($4::text[]) OR e.release_id = ANY($5::text[]))
		        UNION ALL
		        SELECT r.product_id, b.project_id, b.release_id
		        FROM build_runs AS b
		        JOIN projects AS j ON j.id = b.project_id AND j.tenant_id = b.tenant_id
		        JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id AND r.product_id = j.product_id
		        WHERE NOT $2 AND s.artifact_id IS NOT NULL AND b.tenant_id = s.tenant_id
		          AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id', s.artifact_id, 'digest', s.artifact_digest))
		          AND (r.product_id = ANY($3::text[]) AND (s.release_id IS NULL OR r.product_id = s.release_product_id)
		               OR b.project_id = ANY($4::text[]) OR b.release_id = ANY($5::text[]))
		        LIMIT 1
	    ) AS visible ON true
	)`
	if filter.SBOMID != "" {
		var visible bool
		if err := tx.QueryRow(ctx, visibilitySQL+` SELECT EXISTS (SELECT 1 FROM visible_sboms)`, request.TenantID,
			request.TenantWide, request.AllowedProductIDs, request.AllowedProjectIDs, request.AllowedReleaseIDs,
			filter.SBOMID, "", "").Scan(&visible); err != nil {
			return empty, fmt.Errorf("check visible SBOM: %w", err)
		}
		if !visible {
			return empty, evidencequery.ErrNotFound
		}
	}
	statement := fmt.Sprintf(visibilitySQL+`, expanded AS (
	    SELECT s.id || ':' || (component.ordinality - 1)::text AS id,
	           s.id AS sbom_id, s.tenant_id, s.release_id, s.artifact_id,
	           s.format, s.spec_version, s.product_id, s.project_id,
	           s.visible_release_id, component.value AS component
	    FROM visible_sboms AS s
	    CROSS JOIN LATERAL jsonb_array_elements(
	        CASE WHEN jsonb_typeof(s.components) = 'array' THEN s.components ELSE '[]'::jsonb END
	    ) WITH ORDINALITY AS component(value, ordinality)
	    WHERE ($10 = '' OR component.value->>'purl' = $10)
	      AND ($9 = '' OR strpos(lower(coalesce(component.value->>'name', '') || E'\n' ||
	             coalesce(component.value->>'version', '') || E'\n' || coalesce(component.value->>'purl', '')), $9) > 0)
	)
	SELECT id, sbom_id, tenant_id, release_id, artifact_id, format, spec_version,
	       product_id, project_id, visible_release_id, component
	FROM expanded
	WHERE ($11 = '' OR id %s $11)
	ORDER BY id %s LIMIT $12`, comparison, direction)
	rows, err := tx.Query(ctx, statement, request.TenantID, request.TenantWide,
		request.AllowedProductIDs, request.AllowedProjectIDs, request.AllowedReleaseIDs,
		filter.SBOMID, filter.ReleaseID, filter.ArtifactID, filter.Query, filter.PURL,
		cursorID, request.Page.PageSize+1)
	if err != nil {
		return empty, fmt.Errorf("page scoped SBOM components: %w", err)
	}
	defer rows.Close()
	points := make([]evidencequery.SBOMComponentPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point evidencequery.SBOMComponentPoint
		var releaseID, artifactID, productID, projectID, visibleReleaseID sql.NullString
		var componentJSON []byte
		record := &point.Record
		if err := rows.Scan(&record.ID, &record.SBOMID, &point.TenantID,
			&releaseID, &artifactID, &record.Format, &record.SpecVersion,
			&productID, &projectID, &visibleReleaseID, &componentJSON); err != nil {
			return empty, fmt.Errorf("scan SBOM component page: %w", err)
		}
		var component domain.SBOMComponent
		if err := json.Unmarshal(componentJSON, &component); err != nil {
			return empty, evidencequery.ErrConflict
		}
		record.ReleaseID = nullableSQLString(releaseID)
		record.ArtifactID = nullableSQLString(artifactID)
		record.Component = evidencedomain.SBOMComponent{Identity: component.Identity, Name: component.Name, Version: component.Version, PURL: component.PURL}
		point.ProductID = nullableSQLString(productID)
		point.ProjectID = nullableSQLString(projectID)
		point.ReleaseID = nullableSQLString(visibleReleaseID)
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("read SBOM component page: %w", err)
	}
	if len(points) <= request.Page.PageSize {
		return appquery.Result[evidencequery.SBOMComponentPoint]{Items: points}, nil
	}
	points = points[:request.Page.PageSize]
	last := points[len(points)-1].Record.ID
	return appquery.Result[evidencequery.SBOMComponentPoint]{Items: points, Next: &appquery.SortKey{Value: last, ID: last}}, nil
}
