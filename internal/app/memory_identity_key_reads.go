package app

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// LockAPIKeyCreation checks the tenant in this transaction's snapshot. The
// in-memory fixture uses optimistic version checks at commit instead of SQL
// row locks; concurrent commits therefore conflict rather than overwrite.
// It is a test-adapter capability, not a production locking implementation.
func (r memoryIdentityRepository) LockAPIKeyCreation(ctx context.Context, tenantID string) error {
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		return requireMemoryTenant(*state, tenantID)
	})
}

var _ identityapp.APIKeyWriteReader = memoryIdentityRepository{}
