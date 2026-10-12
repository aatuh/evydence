package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.CandidateReleaseReader = releaseCatalog{}
var _ releaseapp.ReleaseCandidateReferenceValidator = releaseCatalog{}

func (r releaseCatalog) ReadCandidateRelease(ctx context.Context, tenant, id string) (releaseapp.CandidateReleaseCoordinates, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, err
	}
	var v releaseapp.CandidateReleaseCoordinates
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(r.id,1025),left(r.tenant_id,1025),left(p.id,1025),octet_length(r.id)>1024 OR octet_length(r.tenant_id)>1024 OR octet_length(p.id)>1024
 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
 WHERE r.tenant_id=$1 AND r.id=$2 FOR SHARE OF r,p`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.CandidateReleaseCoordinates{}, app.ErrNotFound
	}
	if err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, fmt.Errorf("read candidate release coordinates: %w", err)
	}
	if large {
		return releaseapp.CandidateReleaseCoordinates{}, app.ErrConflict
	}
	return v, nil
}

// ValidateReleaseCandidateReferences returns only one existence bit. No
// foreign-context documents, component/finding arrays or artifact metadata
// cross the database boundary. Selected references and their source parents
// remain share-locked through the outer command/replay transaction.
func (r releaseCatalog) ValidateReleaseCandidateReferences(ctx context.Context, tenant, release string, refs releaseapp.ReleaseCandidateReferences) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, release); err != nil {
		return err
	}
	if !releaseapp.ValidCandidateReferences(refs) {
		return app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	var valid bool
	err := r.tx.QueryRow(ctx, `WITH
 builds AS MATERIALIZED (
  SELECT 1 FROM build_runs b JOIN projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id
  JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id
  WHERE b.tenant_id=$1 AND b.id=ANY($3::text[]) AND b.release_id=$2 FOR SHARE OF b,j,r),
 artifacts AS MATERIALIZED (
  SELECT 1 FROM artifacts a WHERE a.tenant_id=$1 AND a.id=ANY($4::text[]) FOR SHARE OF a),
 sboms AS MATERIALIZED (
  SELECT 1 FROM sboms s JOIN evidence_items e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.release_id=s.release_id AND e.type='sbom'
  WHERE s.tenant_id=$1 AND s.id=ANY($5::text[]) AND s.release_id=$2 FOR SHARE OF s,e),
 scans AS MATERIALIZED (
  SELECT 1 FROM vulnerability_scans s JOIN evidence_items e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.release_id=s.release_id AND e.type='vulnerability_scan'
  WHERE s.tenant_id=$1 AND s.id=ANY($6::text[]) AND s.release_id=$2 FOR SHARE OF s,e),
 vex AS MATERIALIZED (
  SELECT 1 FROM vex_documents v JOIN evidence_items e ON e.id=v.evidence_id AND e.tenant_id=v.tenant_id AND e.release_id=v.release_id AND e.type='vex'
  WHERE v.tenant_id=$1 AND v.id=ANY($7::text[]) AND v.release_id=$2 FOR SHARE OF v,e),
 contracts AS MATERIALIZED (
  SELECT 1 FROM openapi_contracts c JOIN evidence_items e ON e.id=c.evidence_id AND e.tenant_id=c.tenant_id AND e.release_id=c.release_id AND e.type='openapi_contract'
  JOIN releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id AND r.product_id=c.product_id
  WHERE c.tenant_id=$1 AND c.id=ANY($8::text[]) AND c.release_id=$2 FOR SHARE OF c,e,r),
 bundles AS MATERIALIZED (
  SELECT 1 FROM release_bundles b WHERE b.tenant_id=$1 AND b.id=ANY($9::text[]) AND b.release_id=$2 FOR SHARE OF b)
 SELECT
  (SELECT count(*)FROM builds)=(SELECT count(DISTINCT id)FROM unnest($3::text[])ids(id))
  AND (SELECT count(*)FROM artifacts)=(SELECT count(DISTINCT id)FROM unnest($4::text[])ids(id))
  AND (SELECT count(*)FROM sboms)=(SELECT count(DISTINCT id)FROM unnest($5::text[])ids(id))
  AND (SELECT count(*)FROM scans)=(SELECT count(DISTINCT id)FROM unnest($6::text[])ids(id))
  AND (SELECT count(*)FROM vex)=(SELECT count(DISTINCT id)FROM unnest($7::text[])ids(id))
  AND (SELECT count(*)FROM contracts)=(SELECT count(DISTINCT id)FROM unnest($8::text[])ids(id))
  AND (SELECT count(*)FROM bundles)=(SELECT count(DISTINCT id)FROM unnest($9::text[])ids(id))`, tenant, release, refs.BuildIDs, refs.ArtifactIDs, refs.SBOMIDs, refs.ScanIDs, refs.VEXIDs, refs.ContractIDs, refs.BundleIDs).Scan(&valid)
	if err != nil {
		return fmt.Errorf("validate candidate reference ownership: %w", err)
	}
	if !valid {
		return app.ErrNotFound
	}
	return nil
}
