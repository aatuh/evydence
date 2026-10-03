package httpapi

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// BuildCommands exposes creation only, without unrelated release commands,
// attestation ingestion or cached catalog state.
type BuildCommands interface {
	CreateBuildRun(context.Context, identitydomain.Actor, releaseapp.CreateBuildRunInput) (releasedomain.BuildRun, error)
}
