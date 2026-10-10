package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (l *Ledger) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	value, err := l.releaseCommands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: name, Slug: slug})
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetProduct(ctx context.Context, actor domain.Actor, id string) (domain.Product, error) {
	value, err := l.releaseCommands.GetProduct(ctx, actor, id)
	return productFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	value, err := l.releaseCommands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: productID, Name: name})
	return projectFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	value, err := l.releaseCommands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: productID, Version: version})
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	value, err := l.releaseCommands.GetRelease(ctx, actor, releaseID)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.FreezeRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string, expectedRevision int64) (domain.Release, error) {
	value, err := l.releaseCommands.ApproveRelease(ctx, actor, releaseID, expectedRevision)
	return domain.ReleaseFromContextModel(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	value, err := l.releaseCommands.RegisterArtifact(ctx, actor, releaseapp.RegisterArtifactInput{Name: name, MediaType: mediaType, Digest: digest, Size: size})
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetArtifact(ctx context.Context, actor domain.Actor, id string) (domain.Artifact, error) {
	value, err := l.releaseCommands.GetArtifact(ctx, actor, id)
	return artifactFromReleaseContext(value), fromReleaseContextError(err)
}
