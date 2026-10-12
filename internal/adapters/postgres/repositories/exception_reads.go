package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.ExceptionCommandReader = decisions{}

func (r decisions) ReadExceptionSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	switch kind {
	case "release", "finding", "control":
	default:
		return riskapp.GovernanceSubjectReference{}, app.ErrValidation
	}
	return governance(r).ReadWaiverSubject(ctx, tenant, kind, id)
}
func (r decisions) ReadExceptionTransitionState(ctx context.Context, tenant, id string) (riskapp.ExceptionTransitionState, error) {
	var v riskapp.ExceptionTransitionState
	if err := governance(r).approvalReadFence(ctx, tenant, id); err != nil {
		return v, err
	}
	v.ID, v.TenantID = id, tenant
	var invalid bool
	err := r.tx.QueryRow(ctx, `SELECT left(release_id,1025),left(COALESCE(finding_id,''),1025),left(COALESCE(control_id,''),1025),approved,expires_at,
 octet_length(release_id)>1024 OR octet_length(COALESCE(finding_id,''))>1024 OR octet_length(COALESCE(control_id,''))>1024
 FROM exceptions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&v.ReleaseID, &v.FindingID, &v.ControlID, &v.Approved, &v.ExpiresAt, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskapp.ExceptionTransitionState{}, app.ErrNotFound
	}
	if err != nil {
		return riskapp.ExceptionTransitionState{}, fmt.Errorf("read bounded exception transition: %w", err)
	}
	if invalid {
		return riskapp.ExceptionTransitionState{}, app.ErrValidation
	}
	v.ExpiresAt = v.ExpiresAt.UTC()
	return v, nil
}
func (r decisions) ReadExceptionForApproval(ctx context.Context, tenant, id string) (riskdomain.Exception, error) {
	var v riskdomain.Exception
	if err := governance(r).approvalReadFence(ctx, tenant, id); err != nil {
		return v, err
	}
	v.ID, v.TenantID = id, tenant
	var invalid bool
	err := r.tx.QueryRow(ctx, `SELECT left(release_id,1025),left(COALESCE(finding_id,''),1025),left(COALESCE(control_id,''),1025),left(reason,65537),left(owner,1025),expires_at,
 approved,left(COALESCE(approved_by,''),1025),approved_at,created_at,
 octet_length(release_id)>1024 OR octet_length(COALESCE(finding_id,''))>1024 OR octet_length(COALESCE(control_id,''))>1024 OR octet_length(reason)>65536 OR octet_length(owner)>1024 OR octet_length(COALESCE(approved_by,''))>1024
 FROM exceptions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&v.ReleaseID, &v.FindingID, &v.ControlID, &v.Reason, &v.Owner, &v.ExpiresAt, &v.Approved, &v.ApprovedBy, &v.ApprovedAt, &v.CreatedAt, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskdomain.Exception{}, app.ErrNotFound
	}
	if err != nil {
		return riskdomain.Exception{}, fmt.Errorf("read bounded exception approval record: %w", err)
	}
	if invalid {
		return riskdomain.Exception{}, app.ErrValidation
	}
	v.ExpiresAt, v.CreatedAt = v.ExpiresAt.UTC(), v.CreatedAt.UTC()
	if v.ApprovedAt != nil {
		at := v.ApprovedAt.UTC()
		v.ApprovedAt = &at
	}
	return v, nil
}
