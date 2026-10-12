package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ReleaseStateCommands exposes lifecycle transitions only, without catalog
// creation, queries, or unrelated workflows.
type ReleaseStateCommands interface {
	AuthorizeReleaseTransition(context.Context, identitydomain.Actor, string) error
	FreezeRelease(context.Context, identitydomain.Actor, string, int64) (releasedomain.Release, error)
	ApproveRelease(context.Context, identitydomain.Actor, string, int64) (releasedomain.Release, error)
}

func mapReleaseStateCommandError(err error) error {
	if revision, ok := releaseapp.CurrentRevision(err); ok {
		return app.NewVersionConflict(revision)
	}
	return mapBuildAttestationCommandError(err)
}
