package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical package-local characterization only. HTTP and runtime policy
// evaluation use the focused command over current transaction repositories.
func (l *Ledger) EvaluateRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.PolicyEvaluation, error) {
	value, err := l.legacyRiskCommands().EvaluateRelease(ctx, actor, releaseID)
	return policyEvaluationFromRiskContext(value), fromRiskContextError(err)
}
