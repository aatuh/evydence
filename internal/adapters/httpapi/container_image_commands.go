package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ContainerImageCommands interface {
	AuthorizeContainerImageRegistration(context.Context, identitydomain.Actor, releaseapp.RegisterContainerImageInput) error
	RegisterContainerImage(context.Context, identitydomain.Actor, releaseapp.RegisterContainerImageInput) (releasedomain.ContainerImage, error)
}

func containerImageFromCommand(v releasedomain.ContainerImage) domain.ContainerImage {
	return domain.ContainerImage{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, Repository: v.Repository, Tag: v.Tag, Digest: v.Digest, Platform: v.Platform, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
