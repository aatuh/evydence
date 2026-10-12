package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// The unchanged historical bundle getter is retained only as a local test oracle.
func (l *Ledger) GetReleaseBundle(ctx context.Context, actor domain.Actor, id string) (domain.ReleaseBundle, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseBundle{}, err
	}
	if err := require(actor, ScopeBundleRead); err != nil {
		return domain.ReleaseBundle{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bundle, ok := l.bundles[strings.TrimSpace(id)]
	if !ok || bundle.TenantID != actor.TenantID {
		return domain.ReleaseBundle{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeBundleRead, resourceRefs{ReleaseID: bundle.ReleaseID}); err != nil {
		return domain.ReleaseBundle{}, err
	}
	return bundle, nil
}
