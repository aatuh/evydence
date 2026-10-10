package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Unchanged aggregate behavior is retained only as a characterization oracle.
func (l *Ledger) CreateReleaseBundle(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseBundle, error) {
	value, err := l.legacyPackageCommands().CreateReleaseBundle(ctx, actor, releaseID)
	return domain.ReleaseBundleFromContextModel(value), fromPackageContextError(err)
}

// Explicit local-memory replay uses current scoped access without generating
// a manifest, signature, audit entry or worker job. The PostgreSQL runtime
// binds the native Package command guard instead of this compatibility helper.
func (l *Ledger) AuthorizeReleaseBundleCreation(ctx context.Context, a domain.Actor, raw string) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeBundleWrite); err != nil {
		return err
	}
	id, err := packageapp.NormalizeReleaseBundleID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeProductReleaseLocked(a, ScopeBundleWrite, "", id)
	return err
}
