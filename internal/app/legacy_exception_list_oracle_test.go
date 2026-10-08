package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical methods are package-local test oracles only.

func (l *Ledger) ListExceptions(ctx context.Context, actor domain.Actor, releaseID string) ([]domain.Exception, error) {
	values, err := l.riskCommands.ListExceptions(ctx, actor, releaseID)
	if err != nil {
		return nil, fromRiskContextError(err)
	}
	result := make([]domain.Exception, 0, len(values))
	for _, value := range values {
		result = append(result, exceptionFromRiskContext(value))
	}
	return result, nil
}
