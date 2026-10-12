package repositories

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (r builds) ReadBuildAttestationCreationScope(ctx context.Context, tenant, id string) (releaseapp.BuildAttestationCreationCoordinates, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	var one int
	err := r.tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.BuildAttestationCreationCoordinates{}, app.ErrNotFound
	}
	if err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	var v releaseapp.BuildAttestationCreationCoordinates
	var raw []byte
	var large bool
	// Only output artifact IDs cross this port. The CASE and per-item predicate
	// bound selected identifiers without transferring source identity or digests.
	err = r.tx.QueryRow(ctx, `SELECT left(b.tenant_id,1025),left(b.id,1025),left(j.id,1025),left(p.id,1025),left(r.id,1025),left(r.product_id,1025),
 octet_length(b.tenant_id)>1024 OR octet_length(b.id)>1024 OR octet_length(j.id)>1024 OR octet_length(p.id)>1024 OR octet_length(r.id)>1024 OR octet_length(r.product_id)>1024,
 CASE WHEN (CASE WHEN jsonb_typeof(b.outputs)='array' THEN jsonb_array_length(b.outputs)<=4096 ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END)o WHERE jsonb_typeof(o) IS DISTINCT FROM 'object' OR (o ? 'artifact_id' AND (jsonb_typeof(o->'artifact_id') IS DISTINCT FROM 'string' OR octet_length(o->>'artifact_id')>1024)))
 THEN CASE WHEN octet_length(ids.value::text)<=1048576 THEN ids.value ELSE NULL END ELSE NULL END
 FROM build_runs b JOIN projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id
 JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id
 JOIN products p ON p.id=j.product_id AND p.tenant_id=b.tenant_id
 CROSS JOIN LATERAL(SELECT COALESCE(jsonb_agg(o->'artifact_id')FILTER(WHERE o ? 'artifact_id'),'[]'::jsonb)value FROM jsonb_array_elements(CASE WHEN (CASE WHEN jsonb_typeof(b.outputs)='array' THEN jsonb_array_length(b.outputs)<=4096 ELSE false END) THEN b.outputs ELSE '[]'::jsonb END)o)ids
 WHERE b.tenant_id=$1 AND b.id=$2 FOR SHARE OF b,j,r,p`, tenant, id).Scan(&v.TenantID, &v.BuildID, &v.ProjectID, &v.ProductID, &v.ReleaseID, &v.ReleaseProductID, &large, &raw)
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 || json.Unmarshal(raw, &v.ArtifactIDs) != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, app.ErrConflict
	}
	return v, nil
}
