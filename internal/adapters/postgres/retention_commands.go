package postgres

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.RetentionPolicyReader = (*Store)(nil)

func (s *Store) ReadObjectRetentionPolicy(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	if s == nil || s.pool == nil {
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrValidation
	}
	policy, err := repositories.ReadObjectRetentionPolicy(ctx, s.pool, tenantID, id, false)
	switch {
	case errors.Is(err, app.ErrValidation):
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrConflict
	default:
		return policy, err
	}
}
