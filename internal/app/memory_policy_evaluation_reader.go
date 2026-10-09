package app

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/application"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.PolicyEvaluationReader = memoryDecisionRepository{}

// Authority-only reads select current owned coordinates, never readiness
// projections. Memory transactions do not model SQL share locks or fences.
func (r memoryDecisionRepository) ReadPolicyEvaluationRelease(ctx context.Context, tenant, release string) (riskapp.GovernanceSubjectReference, error) {
	var out riskapp.GovernanceSubjectReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		out = riskapp.GovernanceSubjectReference{ID: release, TenantID: tenant, Type: "release", ProductID: refs.ProductID, ReleaseID: release}
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = riskapp.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskapp.ErrValidation
	}
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	return out, nil
}

// Reuse the current bounded facts at the explicit transaction-local evaluation
// time. No aggregate, alternate evaluator or projection cache is consulted.
func (r memoryDecisionRepository) ReadPolicyEvaluationSnapshot(ctx context.Context, tenant, release string, at time.Time) (riskapp.ReadinessSnapshot, error) {
	return r.ReadReleaseReadinessSnapshotAt(ctx, tenant, release, at)
}
