package httpapi

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Current artifact identities and grants, never cache-backed authority.
type repositoryIngestionFixtureAuthority struct {
	catalogFixtureCommands
	repositories *app.Repositories
}

type repositoryIngestionFixtureArtifactReader interface {
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

func (f repositoryIngestionFixtureAuthority) readArtifact(ctx context.Context, run func(context.Context, repositoryIngestionFixtureArtifactReader) error) error {
	if ctx == nil {
		return app.ErrValidation
	}
	read := func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(repositoryIngestionFixtureArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, reader)
	}
	if f.repositories != nil {
		return read(ctx, *f.repositories)
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, read)
}

func (f repositoryIngestionFixtureAuthority) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.readArtifact(ctx, func(ctx context.Context, r repositoryIngestionFixtureArtifactReader) error {
		var err error
		out, err = r.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}

func (f repositoryIngestionFixtureAuthority) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return f.readArtifact(ctx, func(ctx context.Context, r repositoryIngestionFixtureArtifactReader) error {
		v, err := r.ReadBuildArtifact(ctx, tenant, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != tenant || digest != "" && !strings.EqualFold(v.Digest, digest) {
			return app.ErrNotFound
		}
		return nil
	})
}
