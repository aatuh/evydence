package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/authz"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type registrationFixtureCatalog interface {
	releaseapp.ArtifactRegistrationReader
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildCreationArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}
type registrationFixtureImages interface {
	releaseapp.ContainerImageIdentityReader
	ContainerImageRegistrationIdentityByKey(context.Context, string, string, string) (releaseapp.ContainerImageRegistrationIdentity, bool, error)
}
type registrationNativeFixture struct{ catalogCreationNativeFixture }

func (f registrationNativeFixture) registrationFacts(ctx context.Context, run func(context.Context, registrationFixtureCatalog) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.ReleaseCatalog.(registrationFixtureCatalog)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	})
}
func (f registrationNativeFixture) imageFacts(ctx context.Context, run func(context.Context, registrationFixtureImages) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.SupplyChain.(registrationFixtureImages)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	})
}
func (f registrationNativeFixture) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	auth, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, request)
}
func (f registrationNativeFixture) AuthorizeExisting(ctx context.Context, a domain.Actor, id string) error {
	return f.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionArtifactsWrite, Resources: application.ResourceReferences{ArtifactID: id}})
}
func (f registrationNativeFixture) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.registrationFacts(ctx, func(ctx context.Context, r registrationFixtureCatalog) error {
		var err error
		out, err = r.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}
func (f registrationNativeFixture) ArtifactIdentityByDigest(ctx context.Context, tenant, digest string) (releaseapp.ArtifactRegistrationIdentity, bool, error) {
	var out releaseapp.ArtifactRegistrationIdentity
	var found bool
	err := f.registrationFacts(ctx, func(ctx context.Context, r registrationFixtureCatalog) error {
		var err error
		out, found, err = r.ArtifactIdentityByDigest(ctx, tenant, digest)
		return err
	})
	if err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	return out, found, nil
}
func (f registrationNativeFixture) ReadArtifactMetadata(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if f.readOnly {
		panic("artifact replay inspected private metadata")
	}
	var out releasedomain.Artifact
	err := f.registrationFacts(ctx, func(ctx context.Context, r registrationFixtureCatalog) error {
		var err error
		out, err = r.ReadArtifactMetadata(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f registrationNativeFixture) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if f.readOnly {
		panic("image replay inspected artifact digest")
	}
	var out releasedomain.Artifact
	err := f.registrationFacts(ctx, func(ctx context.Context, r registrationFixtureCatalog) error {
		var err error
		out, err = r.ReadBuildArtifact(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f registrationNativeFixture) ReadContainerImageRegistrationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	var out releasedomain.Artifact
	err := f.registrationFacts(ctx, func(ctx context.Context, r registrationFixtureCatalog) error {
		var err error
		out, err = r.ReadBuildCreationArtifact(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f registrationNativeFixture) ContainerImageRegistrationIdentityByKey(ctx context.Context, tenant, repository, digest string) (releaseapp.ContainerImageRegistrationIdentity, bool, error) {
	var out releaseapp.ContainerImageRegistrationIdentity
	var found bool
	err := f.imageFacts(ctx, func(ctx context.Context, r registrationFixtureImages) error {
		var err error
		out, found, err = r.ContainerImageRegistrationIdentityByKey(ctx, tenant, repository, digest)
		return err
	})
	if err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	return out, found, nil
}
func (f registrationNativeFixture) ContainerImageByRepositoryDigest(ctx context.Context, tenant, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	if f.readOnly {
		panic("image replay inspected private metadata")
	}
	var out releasedomain.ContainerImage
	var found bool
	err := f.imageFacts(ctx, func(ctx context.Context, r registrationFixtureImages) error {
		var err error
		out, found, err = r.ContainerImageByRepositoryDigest(ctx, tenant, repository, digest)
		return err
	})
	if err != nil {
		return releasedomain.ContainerImage{}, false, err
	}
	return out, found, nil
}
func (f registrationNativeFixture) ExecuteArtifact(ctx context.Context, run func(context.Context, releaseapp.ArtifactTransaction) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		if _, ok := r.ReleaseCatalog.(registrationFixtureCatalog); !ok || r.Audit == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	})
}
func (f registrationNativeFixture) ExecuteContainerImage(ctx context.Context, run func(context.Context, releaseapp.ContainerImageTransaction) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		_, catalog := r.ReleaseCatalog.(registrationFixtureCatalog)
		_, images := r.SupplyChain.(registrationFixtureImages)
		if !catalog || !images || r.Audit == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	})
}
func (f registrationNativeFixture) InsertArtifact(ctx context.Context, v releasedomain.Artifact) error {
	if f.readOnly || f.repositories == nil {
		panic("artifact preflight/unbound write")
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: v.ID, TenantID: v.TenantID, Name: v.Name, MediaType: v.MediaType, Digest: v.Digest, Size: v.Size, CreatedAt: v.CreatedAt}))
}
func (f registrationNativeFixture) InsertContainerImage(ctx context.Context, v releasedomain.ContainerImage) error {
	if f.readOnly || f.repositories == nil {
		panic("image preflight/unbound write")
	}
	return releaseFixtureCoreError(f.repositories.SupplyChain.InsertContainerImage(ctx, domain.ContainerImage{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, Repository: v.Repository, Tag: v.Tag, Digest: v.Digest, Platform: v.Platform, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (f registrationFixtureCommands) nativeArtifact(readOnly bool) (*releaseapp.ArtifactCommands, error) {
	base, clock, ids := f.nativeCatalog(readOnly)
	ports := registrationNativeFixture{base}
	return releaseapp.NewArtifactCommands(releaseapp.ArtifactCommandConfig{Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
func (f registrationFixtureCommands) nativeImage(readOnly bool) (*releaseapp.ContainerImageCommands, error) {
	base, clock, ids := f.nativeCatalog(readOnly)
	ports := registrationNativeFixture{base}
	return releaseapp.NewContainerImageCommands(releaseapp.ContainerImageCommandConfig{Reader: ports, Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
