package app

import (
	"context"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var (
	_ riskapp.WaiverCommandReader    = memoryGovernanceRepository{}
	_ riskapp.ApprovalReader         = memoryGovernanceRepository{}
	_ riskapp.ExceptionCommandReader = memoryDecisionRepository{}
)

func (r memoryGovernanceRepository) readSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	var value riskapp.GovernanceSubjectReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		value, err = memoryGovernanceOwner(state, tenant, kind, id)
		return err
	})
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	value.Type, value.ID = kind, id
	return value, nil
}

func (r memoryGovernanceRepository) ReadWaiverSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	switch kind {
	case "release", "finding", "control", "policy":
		return r.readSubject(ctx, tenant, kind, id)
	default:
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
}

func (r memoryGovernanceRepository) ReadApprovalSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	switch kind {
	case "release", "contract_diff", "waiver", "security_review", "customer_package":
		return r.readSubject(ctx, tenant, kind, id)
	default:
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
}

func (r memoryGovernanceRepository) ApprovalEvidenceExists(ctx context.Context, tenant, id string) (bool, error) {
	var exists bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Evidence[id]
		exists = ok && v.ID == id && v.TenantID == tenant
		return nil
	})
	return exists, err
}

func (r memoryGovernanceRepository) ReadWaiverTransitionState(ctx context.Context, tenant, id string) (riskapp.WaiverTransitionState, error) {
	var result riskapp.WaiverTransitionState
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Waivers[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.ScopeType, 128) || !memoryGovernanceText(v.ScopeID, 1024) || !memoryGovernanceText(v.SupersededBy, 1024) {
			return ErrValidation
		}
		result = riskapp.WaiverTransitionState{ID: id, TenantID: tenant, ScopeType: v.ScopeType, ScopeID: v.ScopeID, SupersededBy: v.SupersededBy, Approved: v.Approved, ExpiresAt: v.ExpiresAt.UTC()}
		return nil
	})
	return result, err
}

func (r memoryGovernanceRepository) ReadWaiverForApproval(ctx context.Context, tenant, id string) (riskdomain.Waiver, error) {
	var result riskdomain.Waiver
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Waivers[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.ScopeType, 128) || !memoryGovernanceText(v.Reason, 65536) {
			return ErrValidation
		}
		for _, text := range []string{v.ScopeID, v.ControlID, v.PolicyID, v.Owner, v.Risk, v.ApprovedBy, v.Supersedes, v.SupersededBy, v.SchemaVersion} {
			if !memoryGovernanceText(text, 1024) {
				return ErrValidation
			}
		}
		v.ExpiresAt, v.CreatedAt = v.ExpiresAt.UTC(), v.CreatedAt.UTC()
		if v.ApprovedAt != nil {
			at := v.ApprovedAt.UTC()
			v.ApprovedAt = &at
		}
		result = riskdomain.Waiver(v)
		return nil
	})
	return result, err
}

func (r memoryDecisionRepository) ReadExceptionSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	switch kind {
	case "release", "finding", "control":
		return memoryGovernanceRepository(r).readSubject(ctx, tenant, kind, id)
	default:
		return riskapp.GovernanceSubjectReference{}, ErrValidation
	}
}

func (r memoryDecisionRepository) ReadExceptionTransitionState(ctx context.Context, tenant, id string) (riskapp.ExceptionTransitionState, error) {
	var result riskapp.ExceptionTransitionState
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Exceptions[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		for _, text := range []string{v.ReleaseID, v.FindingID, v.ControlID} {
			if !memoryGovernanceText(text, 1024) {
				return ErrValidation
			}
		}
		result = riskapp.ExceptionTransitionState{ID: id, TenantID: tenant, ReleaseID: v.ReleaseID, FindingID: v.FindingID, ControlID: v.ControlID, Approved: v.Approved, ExpiresAt: v.ExpiresAt.UTC()}
		return nil
	})
	return result, err
}

func (r memoryDecisionRepository) ReadExceptionForApproval(ctx context.Context, tenant, id string) (riskdomain.Exception, error) {
	var result riskdomain.Exception
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.Exceptions[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.Reason, 65536) {
			return ErrValidation
		}
		for _, text := range []string{v.ReleaseID, v.FindingID, v.ControlID, v.Owner, v.ApprovedBy} {
			if !memoryGovernanceText(text, 1024) {
				return ErrValidation
			}
		}
		v.ExpiresAt, v.CreatedAt = v.ExpiresAt.UTC(), v.CreatedAt.UTC()
		if v.ApprovedAt != nil {
			at := v.ApprovedAt.UTC()
			v.ApprovedAt = &at
		}
		result = riskdomain.Exception(v)
		return nil
	})
	return result, err
}
