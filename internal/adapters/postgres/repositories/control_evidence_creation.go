package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.ControlEvidenceReader = controls{}
var _ riskapp.ControlEvidenceArtifactGrantReader = controls{}

func (r controls) LockControlEvidenceTenant(ctx context.Context, tenant string) error {
	return r.lockControlTenant(ctx, tenant)
}

func (r controls) ControlEvidenceControlExists(ctx context.Context, tenant, id string) (bool, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return false, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT true FROM security_controls c JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2 FOR SHARE OF c,f`, tenant, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read control link parent: %w", err)
	}
	return exists, nil
}

func (r controls) ReadControlEvidenceSubject(ctx context.Context, tenant string, key riskapp.ControlEvidenceSubjectKey) (riskapp.ControlEvidenceSubjectCoordinates, error) {
	var empty riskapp.ControlEvidenceSubjectCoordinates
	if err := validBuildIdentityRead(ctx, r.tx, tenant, key.SubjectID); err != nil {
		return empty, err
	}
	for _, id := range []string{key.SubjectType, key.ProductID, key.ReleaseID} {
		if id != "" {
			if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
				return empty, err
			}
		}
	}
	projection := controlEvidenceSubjectProjection(key.SubjectType)
	if projection == "" {
		return empty, app.ErrNotFound
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	limit := "2"
	if key.SubjectType == "artifact" {
		limit = "1"
	}
	rows, err := r.tx.Query(ctx, controlEvidenceParentCTEs+` SELECT left(COALESCE(s.product_id,''),1025),left(COALESCE(s.project_id,''),1025),left(COALESCE(s.release_id,''),1025),octet_length(COALESCE(s.product_id,''))>1024 OR octet_length(COALESCE(s.project_id,''))>1024 OR octet_length(COALESCE(s.release_id,''))>1024 FROM (`+projection+`) s WHERE ($3::text='' OR s.product_id=$3) AND ($4::text='' OR s.release_id=$4) LIMIT `+limit, tenant, key.SubjectID, key.ProductID, key.ReleaseID)
	if err != nil {
		return empty, fmt.Errorf("read control evidence subject coordinates: %w", err)
	}
	defer rows.Close()
	v := riskapp.ControlEvidenceSubjectCoordinates{TenantID: tenant, SubjectType: key.SubjectType, SubjectID: key.SubjectID}
	count := 0
	for rows.Next() {
		var large bool
		if err := rows.Scan(&v.ProductID, &v.ProjectID, &v.ReleaseID, &large); err != nil {
			return empty, fmt.Errorf("scan control subject coordinates: %w", err)
		}
		if large {
			return empty, app.ErrValidation
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate control subject coordinates: %w", err)
	}
	if count == 0 {
		return empty, app.ErrNotFound
	}
	if count > 1 {
		return empty, app.ErrConflict
	}
	return v, nil
}

func (r controls) ReadControlEvidenceLink(ctx context.Context, tenant string, key riskapp.ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error) {
	var empty riskdomain.ControlEvidence
	if err := validBuildIdentityRead(ctx, r.tx, tenant, key.ControlID); err != nil {
		return empty, false, err
	}
	if !riskapp.ValidControlEvidenceLinkKey(tenant, key) {
		return empty, false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, false, err
	}
	var v riskdomain.ControlEvidence
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(l.id,1025),l.tenant_id,l.control_id,l.evidence_type,l.subject_type,l.subject_id,COALESCE(l.product_id,''),COALESCE(l.release_id,''),left(l.confidence,65),left(COALESCE(l.notes,''),65537),left(l.schema_version,65),l.created_at,octet_length(l.id)>1024 OR octet_length(l.confidence)>64 OR octet_length(COALESCE(l.notes,''))>65536 OR octet_length(l.schema_version)>64 FROM control_evidence l JOIN security_controls c ON c.id=l.control_id AND c.tenant_id=l.tenant_id JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE l.tenant_id=$1 AND l.control_id=$2 AND l.evidence_type=$3 AND l.subject_type=$4 AND l.subject_id=$5 AND COALESCE(l.product_id,'')=$6 AND COALESCE(l.release_id,'')=$7 FOR SHARE OF l,c,f`, tenant, key.ControlID, key.EvidenceType, key.SubjectType, key.SubjectID, key.ProductID, key.ReleaseID).Scan(&v.ID, &v.TenantID, &v.ControlID, &v.EvidenceType, &v.SubjectType, &v.SubjectID, &v.ProductID, &v.ReleaseID, &v.Confidence, &v.Notes, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, fmt.Errorf("read control evidence duplicate: %w", err)
	}
	if large {
		return empty, false, app.ErrValidation
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, true, nil
}

func (r controls) ControlEvidenceArtifactVisible(ctx context.Context, request riskapp.ControlEvidenceArtifactGrantRequest) (bool, error) {
	if err := validBuildIdentityRead(ctx, r.tx, request.TenantID, request.ArtifactID); err != nil {
		return false, err
	}
	if !riskapp.ValidControlEvidenceArtifactGrantRequest(request) {
		return false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, request.TenantID); err != nil {
		return false, err
	}
	var visible bool
	err := r.tx.QueryRow(ctx, controlEvidenceParentCTEs+` SELECT EXISTS(SELECT 1 FROM (`+controlEvidenceArtifactAssociations+`) s WHERE ($3::text='' OR s.product_id=$3) AND ($4::text='' OR s.release_id=$4) AND (s.product_id=ANY($5::text[]) OR s.project_id=ANY($6::text[]) OR s.release_id=ANY($7::text[])))`, request.TenantID, request.ArtifactID, request.ProductID, request.ReleaseID, request.AllowedProductIDs, request.AllowedProjectIDs, request.AllowedReleaseIDs).Scan(&visible)
	if err != nil {
		return false, fmt.Errorf("read scoped control artifact grant: %w", err)
	}
	return visible, nil
}
