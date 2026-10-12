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

var _ riskapp.WaiverCommandReader = governance{}

func (r governance) ReadWaiverSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	if err := r.approvalReadFence(ctx, tenant, id); err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	switch kind {
	case "release", "finding", "control", "policy":
	default:
		return riskapp.GovernanceSubjectReference{}, app.ErrValidation
	}
	v, err := r.readApprovalOwner(ctx, tenant, kind, id)
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	v.Type, v.ID = kind, id
	return v, nil
}
func (r governance) ReadWaiverTransitionState(ctx context.Context, tenant, id string) (riskapp.WaiverTransitionState, error) {
	var v riskapp.WaiverTransitionState
	if err := r.approvalReadFence(ctx, tenant, id); err != nil {
		return v, err
	}
	v.ID, v.TenantID = id, tenant
	var invalid bool
	err := r.tx.QueryRow(ctx, `SELECT left(scope_type,129),left(scope_id,1025),left(COALESCE(superseded_by,''),1025),approved,expires_at,
 octet_length(scope_type)>128 OR octet_length(scope_id)>1024 OR octet_length(COALESCE(superseded_by,''))>1024
 FROM waivers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&v.ScopeType, &v.ScopeID, &v.SupersededBy, &v.Approved, &v.ExpiresAt, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskapp.WaiverTransitionState{}, app.ErrNotFound
	}
	if err != nil {
		return riskapp.WaiverTransitionState{}, fmt.Errorf("read bounded waiver transition: %w", err)
	}
	if invalid {
		return riskapp.WaiverTransitionState{}, app.ErrValidation
	}
	v.ExpiresAt = v.ExpiresAt.UTC()
	return v, nil
}
func (r governance) ReadWaiverForApproval(ctx context.Context, tenant, id string) (riskdomain.Waiver, error) {
	var v riskdomain.Waiver
	if err := r.approvalReadFence(ctx, tenant, id); err != nil {
		return v, err
	}
	v.ID, v.TenantID = id, tenant
	var invalid bool
	err := r.tx.QueryRow(ctx, `SELECT left(scope_type,129),left(scope_id,1025),left(COALESCE(control_id,''),1025),left(COALESCE(policy_id,''),1025),left(owner,1025),left(risk,1025),left(reason,65537),expires_at,
 approved,left(COALESCE(approved_by,''),1025),approved_at,left(COALESCE(supersedes,''),1025),left(COALESCE(superseded_by,''),1025),left(schema_version,1025),created_at,
 octet_length(scope_type)>128 OR octet_length(scope_id)>1024 OR octet_length(COALESCE(control_id,''))>1024 OR octet_length(COALESCE(policy_id,''))>1024 OR octet_length(owner)>1024 OR octet_length(risk)>1024 OR octet_length(reason)>65536 OR octet_length(COALESCE(approved_by,''))>1024 OR octet_length(COALESCE(supersedes,''))>1024 OR octet_length(COALESCE(superseded_by,''))>1024 OR octet_length(schema_version)>1024
 FROM waivers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&v.ScopeType, &v.ScopeID, &v.ControlID, &v.PolicyID, &v.Owner, &v.Risk, &v.Reason, &v.ExpiresAt, &v.Approved, &v.ApprovedBy, &v.ApprovedAt, &v.Supersedes, &v.SupersededBy, &v.SchemaVersion, &v.CreatedAt, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskdomain.Waiver{}, app.ErrNotFound
	}
	if err != nil {
		return riskdomain.Waiver{}, fmt.Errorf("read bounded waiver approval record: %w", err)
	}
	if invalid {
		return riskdomain.Waiver{}, app.ErrValidation
	}
	v.ExpiresAt, v.CreatedAt = v.ExpiresAt.UTC(), v.CreatedAt.UTC()
	if v.ApprovedAt != nil {
		at := v.ApprovedAt.UTC()
		v.ApprovedAt = &at
	}
	return v, nil
}
