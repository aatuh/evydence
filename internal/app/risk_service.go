package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) EvaluateRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.PolicyEvaluation, error) {
	value, err := l.riskCommands.EvaluateRelease(ctx, actor, releaseID)
	return policyEvaluationFromRiskContext(value), fromRiskContextError(err)
}
