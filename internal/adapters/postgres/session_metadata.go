package postgres

import (
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func sessionLifecycleMetadata(session domain.SSOSession) (int64, int64, error) {
	policy, ok := identitydomain.SSOSession(session).LifecyclePolicy()
	if !ok {
		return 0, 0, app.ErrValidation
	}
	return int64(policy.MaximumLifetime / time.Second), int64(policy.IdleTimeout / time.Second), nil
}
