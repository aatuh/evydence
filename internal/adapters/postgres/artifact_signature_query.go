package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.ArtifactSignatureReader = (*Store)(nil)

// GetArtifactSignaturePoint reads a tenant-owned signature only when its
// artifact and digest still match. A scoped human gets at most one current,
// tenant-verified evidence or build association from the same SQL snapshot.
func (s *Store) GetArtifactSignaturePoint(ctx context.Context, request verificationquery.SignatureReadRequest) (verificationquery.SignaturePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedProjectIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedProjectIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return verificationquery.SignaturePoint{}, verificationquery.ErrSignatureValidation
	}
	request.ID = strings.TrimSpace(request.ID)
	if request.ID == "" {
		return verificationquery.SignaturePoint{}, verificationquery.ErrSignatureNotFound
	}
	var point verificationquery.SignaturePoint
	var keyID, payloadRef, payloadHash, productID, projectID, releaseID sql.NullString
	sig := &point.Signature
	err := s.pool.QueryRow(ctx, `
		SELECT s.id, s.tenant_id, s.artifact_id, s.subject_digest,
		       s.algorithm, s.key_id, s.signature, s.payload_ref,
		       s.payload_hash, s.verification_status, s.schema_version,
		       s.created_at, a.digest, visible.product_id,
		       visible.project_id, visible.release_id
		FROM artifact_signatures AS s
		JOIN artifacts AS a ON a.id = s.artifact_id AND a.tenant_id = s.tenant_id
		    AND a.digest = s.subject_digest
		LEFT JOIN LATERAL (
		    SELECT e.product_id, e.project_id, e.release_id
		    FROM evidence_items AS e
		    LEFT JOIN products AS ep ON ep.id = e.product_id AND ep.tenant_id = e.tenant_id
		    LEFT JOIN projects AS ej ON ej.id = e.project_id AND ej.tenant_id = e.tenant_id
		    LEFT JOIN releases AS er ON er.id = e.release_id AND er.tenant_id = e.tenant_id
		    WHERE NOT $6 AND e.tenant_id = s.tenant_id
		      AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', s.artifact_id))
		      AND (e.product_id IS NULL OR ep.id IS NOT NULL)
		      AND (e.project_id IS NULL OR ej.id IS NOT NULL)
		      AND (e.release_id IS NULL OR er.id IS NOT NULL)
		      AND (e.product_id IS NULL OR e.project_id IS NULL OR e.product_id = ej.product_id)
		      AND (e.product_id IS NULL OR e.release_id IS NULL OR e.product_id = er.product_id)
		      AND (e.project_id IS NULL OR e.release_id IS NULL OR ej.product_id = er.product_id)
		      AND (e.product_id = ANY($3::text[]) OR e.project_id = ANY($4::text[]) OR e.release_id = ANY($5::text[]))
		    UNION ALL
		    SELECT r.product_id, b.project_id, b.release_id
		    FROM build_runs AS b
		    JOIN projects AS j ON j.id = b.project_id AND j.tenant_id = b.tenant_id
		    JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
		        AND r.product_id = j.product_id
		    WHERE NOT $6 AND b.tenant_id = s.tenant_id
		      AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id', s.artifact_id, 'digest', s.subject_digest))
		      AND (r.product_id = ANY($3::text[]) OR b.project_id = ANY($4::text[]) OR b.release_id = ANY($5::text[]))
		    LIMIT 1
		) AS visible ON true
		WHERE s.tenant_id = $1 AND s.id = $2`,
		request.TenantID, request.ID, request.AllowedProductIDs,
		request.AllowedProjectIDs, request.AllowedReleaseIDs, request.TenantWide).Scan(
		&sig.ID, &sig.TenantID, &sig.ArtifactID, &sig.SubjectDigest,
		&sig.Algorithm, &keyID, &sig.Signature, &payloadRef,
		&payloadHash, &sig.VerificationStatus, &sig.SchemaVersion,
		&sig.CreatedAt, &point.ArtifactDigest, &productID,
		&projectID, &releaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return verificationquery.SignaturePoint{}, verificationquery.ErrSignatureNotFound
	}
	if err != nil {
		return verificationquery.SignaturePoint{}, fmt.Errorf("get artifact signature point: %w", err)
	}
	sig.KeyID = nullableSQLString(keyID)
	sig.PayloadRef = nullableSQLString(payloadRef)
	sig.PayloadHash = nullableSQLString(payloadHash)
	point.ProductID = nullableSQLString(productID)
	point.ProjectID = nullableSQLString(projectID)
	point.ReleaseID = nullableSQLString(releaseID)
	return point, nil
}
