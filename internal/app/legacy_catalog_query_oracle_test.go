package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical algorithms remain package-local test oracles only.
func (l *Ledger) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	values, err := l.releaseCommands.ListProducts(ctx, actor)
	if err != nil {
		return nil, fromReleaseContextError(err)
	}
	result := make([]domain.Product, 0, len(values))
	for _, value := range values {
		result = append(result, productFromReleaseContext(value))
	}
	return result, nil
}

func (l *Ledger) GetProject(ctx context.Context, actor domain.Actor, id string) (domain.Project, error) {
	value, err := l.releaseCommands.GetProject(ctx, actor, id)
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}
