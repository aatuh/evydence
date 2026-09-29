package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.ArtifactPointReader = (*Store)(nil)

// GetArtifactPoint reads one tenant-owned artifact and its current grant
// visibility in the same statement. Association rows never leave PostgreSQL.
func (s *Store) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedProjectIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedProjectIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	request.ID = strings.TrimSpace(request.ID)
	if request.ID == "" {
		return releasequery.ArtifactPoint{}, releasequery.ErrNotFound
	}
	var point releasequery.ArtifactPoint
	artifact := &point.Artifact
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.tenant_id, a.name, a.media_type, a.size, a.digest, a.created_at,
		       ($3::boolean OR EXISTS (
		           SELECT 1 FROM evidence_items AS e
		           LEFT JOIN products AS ep ON ep.id = e.product_id AND ep.tenant_id = e.tenant_id
		           LEFT JOIN projects AS ej ON ej.id = e.project_id AND ej.tenant_id = e.tenant_id
		           LEFT JOIN releases AS er ON er.id = e.release_id AND er.tenant_id = e.tenant_id
		           WHERE e.tenant_id = a.tenant_id
		             AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', a.id))
		             AND (e.product_id IS NULL OR ep.id IS NOT NULL)
		             AND (e.project_id IS NULL OR ej.id IS NOT NULL)
		             AND (e.release_id IS NULL OR er.id IS NOT NULL)
		             AND (e.product_id IS NULL OR e.project_id IS NULL OR e.product_id = ej.product_id)
		             AND (e.product_id IS NULL OR e.release_id IS NULL OR e.product_id = er.product_id)
		             AND (e.project_id IS NULL OR e.release_id IS NULL OR ej.product_id = er.product_id)
		             AND (e.product_id = ANY($4::text[]) OR e.project_id = ANY($5::text[]) OR e.release_id = ANY($6::text[]))
		       ) OR EXISTS (
		           SELECT 1 FROM build_runs AS b
		           JOIN projects AS j ON j.id = b.project_id AND j.tenant_id = b.tenant_id
		           JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
		               AND r.product_id = j.product_id
		           JOIN products AS p ON p.id = r.product_id AND p.tenant_id = b.tenant_id
		           WHERE b.tenant_id = a.tenant_id
		             AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id', a.id, 'digest', a.digest))
		             AND (r.product_id = ANY($4::text[]) OR b.project_id = ANY($5::text[]) OR b.release_id = ANY($6::text[]))
		       )) AS visible
		FROM artifacts AS a WHERE a.tenant_id = $1 AND a.id = $2`,
		request.TenantID, request.ID, request.TenantWide, request.AllowedProductIDs,
		request.AllowedProjectIDs, request.AllowedReleaseIDs).Scan(
		&artifact.ID, &artifact.TenantID, &artifact.Name, &artifact.MediaType,
		&artifact.Size, &artifact.Digest, &artifact.CreatedAt, &point.Visible)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasequery.ArtifactPoint{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasequery.ArtifactPoint{}, fmt.Errorf("get artifact point: %w", err)
	}
	return point, nil
}
