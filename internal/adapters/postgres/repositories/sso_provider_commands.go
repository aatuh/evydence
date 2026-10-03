package repositories

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

var _ identityapp.SSOProviderWriteReader = identity{}

func (r identity) LockSSOProviderCreation(ctx context.Context, tenant string) error {
	return r.LockAPIKeyCreation(ctx, tenant)
}
