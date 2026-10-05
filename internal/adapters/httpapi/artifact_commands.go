package httpapi

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ArtifactCommands exposes registration without the unrelated release catalog.
type ArtifactCommands interface {
	AuthorizeArtifactRegistration(context.Context, identitydomain.Actor, releaseapp.RegisterArtifactInput) error
	RegisterArtifact(context.Context, identitydomain.Actor, releaseapp.RegisterArtifactInput) (releasedomain.Artifact, error)
}
