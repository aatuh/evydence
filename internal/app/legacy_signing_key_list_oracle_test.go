package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ListSigningKeys(ctx context.Context, actor domain.Actor) ([]domain.SigningKey, error) {
	values, err := l.verificationCommands.ListSigningKeys(ctx, actor)
	if err != nil {
		return nil, fromVerificationContextError(err)
	}
	result := make([]domain.SigningKey, 0, len(values))
	for _, value := range values {
		result = append(result, signingKeyFromVerificationContext(value, nil))
	}
	return result, nil
}
