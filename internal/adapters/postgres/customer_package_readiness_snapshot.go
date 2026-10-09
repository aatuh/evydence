package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// Reuse Risk's bounded fact reader and canonical evaluator in the caller's
// read-only snapshot. Package owns only the public DTO translation. No policy
// evaluation, verification receipt, audit entry or other record is persisted.
func readCustomerPackageReadinessTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, now time.Time, budget *customerSnapshotBudget) ([]packagedomain.PolicyCheckSnapshot, error) {
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return nil, err
	}
	now = now.UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return nil, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	if release == "" {
		return nil, nil
	}
	facts, err := readReleaseReadinessSnapshotBoundedTx(ctx, tx, tenant, release, now, budget.remainingBytes)
	if errors.Is(err, riskapp.ErrNotFound) {
		return nil, packageapp.ErrNotFound
	}
	if errors.Is(err, riskapp.ErrValidation) {
		return nil, packageapp.ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if facts.TenantID != tenant || facts.ProductID != product || facts.ReleaseID != release {
		return nil, packageapp.ErrConflict
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(facts, now)
	if err != nil {
		return nil, packageapp.ErrConflict
	}
	checks := make([]packagedomain.PolicyCheckSnapshot, 0, len(evaluation.Checks))
	for _, v := range evaluation.Checks {
		checks = append(checks, packagedomain.PolicyCheckSnapshot{Name: v.Name, Result: v.Result, Severity: v.Severity, Missing: append([]string(nil), v.Missing...), Explanation: v.Explanation, Remediation: v.Remediation})
	}
	body, err := json.Marshal(checks)
	if err != nil || len(body) > budget.remainingBytes {
		return nil, packageapp.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	budget.remainingBytes -= len(body)
	return checks, nil
}
