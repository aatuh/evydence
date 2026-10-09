package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// Reuse current Risk facts and its canonical evaluator. This adds no policy
// receipt or verification write and does not consult aggregate caches.
func readMemoryCustomerPackageReadiness(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, at time.Time, budget *memoryCustomerSnapshotBudget) ([]packagedomain.PolicyCheckSnapshot, error) {
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return nil, err
	}
	at = at.UTC()
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return nil, ErrValidation
	}
	if release == "" {
		return nil, nil
	}
	facts, err := readMemoryReadinessSnapshot(ctx, s, tenant, release, at)
	if errors.Is(err, ErrValidation) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if facts.TenantID != tenant || facts.ProductID != product || facts.ReleaseID != release {
		return nil, ErrConflict
	}
	raw, err := json.Marshal(facts)
	if err != nil || len(raw) > budget.remainingBytes {
		return nil, ErrConflict
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(facts, at)
	if err != nil {
		return nil, ErrConflict
	}
	checks := make([]packagedomain.PolicyCheckSnapshot, 0, len(evaluation.Checks))
	for _, c := range evaluation.Checks {
		checks = append(checks, packagedomain.PolicyCheckSnapshot{Name: c.Name, Result: c.Result, Severity: c.Severity, Missing: slices.Clone(c.Missing), Explanation: c.Explanation, Remediation: c.Remediation})
	}
	raw, err = json.Marshal(checks)
	if err != nil {
		return nil, ErrConflict
	}
	working := *budget
	if err := working.chargeJSON(raw); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return checks, nil
}
