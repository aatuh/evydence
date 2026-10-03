package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ReleaseCreationCommands does not expose transitions or unrelated catalogs.
type ReleaseCreationCommands interface {
	CreateRelease(context.Context, identitydomain.Actor, releaseapp.CreateReleaseInput) (releasedomain.Release, error)
}

func releaseFromCommand(v releasedomain.Release) domain.Release {
	return domain.Release{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Version: v.Version, State: v.State.String(), Revision: v.Revision, CreatedAt: v.CreatedAt, FrozenAt: v.FrozenAt, ApprovedAt: v.ApprovedAt}
}
