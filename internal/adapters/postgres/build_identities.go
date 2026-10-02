package postgres

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releaseapp.BuildIdentityReader = (*Store)(nil)
var _ releaseapp.BuildAttestationSnapshotReader = (*Store)(nil)

func (s *Store) ReadBuildAttestationBuild(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	if s == nil || s.pool == nil {
		return releasedomain.BuildRun{}, app.ErrValidation
	}
	return repositories.ReadBuildAttestationBuild(ctx, s.pool, tenant, id, false)
}

func (s *Store) ReadBuildProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	if s == nil || s.pool == nil {
		return releasedomain.Project{}, app.ErrValidation
	}
	return repositories.ReadBuildProject(ctx, s.pool, tenant, id, false)
}
func (s *Store) ReadBuildRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	if s == nil || s.pool == nil {
		return releasedomain.Release{}, app.ErrValidation
	}
	return repositories.ReadBuildRelease(ctx, s.pool, tenant, id, false)
}
func (s *Store) ReadBuildArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if s == nil || s.pool == nil {
		return releasedomain.Artifact{}, app.ErrValidation
	}
	return repositories.ReadBuildArtifact(ctx, s.pool, tenant, id, false)
}
func (s *Store) ReadBuildArtifactGrant(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	if s == nil || s.pool == nil {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	return repositories.ReadArtifactGrant(ctx, s.pool, request)
}
