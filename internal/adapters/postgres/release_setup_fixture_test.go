package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type postgresReleaseFixtureFacts interface {
	releaseapp.CatalogCreationGuardReader
	releaseapp.ProductSlugReader
	releaseapp.ProductCoordinateReader
	releaseapp.ReleaseVersionReader
	releaseapp.ArtifactRegistrationReader
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}
type postgresReleaseSetupFixture struct {
	execute func(context.Context, app.UnitOfWorkCommand) error
	repos   *app.Repositories
}

// Commands use the actual caller-owned transaction factory/current rows, never
// a Ledger locator or published cache. Native replay contexts join that unit.
func postgresReleaseSetup(factory app.UnitOfWorkFactory) postgresReleaseSetupFixture {
	return postgresReleaseSetupFixture{execute: func(ctx context.Context, run app.UnitOfWorkCommand) error {
		return app.ExecuteUnitOfWork(ctx, factory, run)
	}}
}
func postgresReleaseFixtureError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return releaseapp.ErrNotFound
	case errors.Is(err, app.ErrForbidden):
		return releaseapp.ErrForbidden
	case errors.Is(err, app.ErrConflict):
		return releaseapp.ErrConflict
	default:
		return err
	}
}
func (f postgresReleaseSetupFixture) read(ctx context.Context, run func(context.Context, app.Repositories, postgresReleaseFixtureFacts) error) error {
	use := func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.ReleaseCatalog.(postgresReleaseFixtureFacts)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, r, facts)
	}
	if f.repos != nil {
		return postgresReleaseFixtureError(use(ctx, *f.repos))
	}
	return postgresReleaseFixtureError(f.execute(ctx, use))
}
func (f postgresReleaseSetupFixture) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != releaseapp.ScopeEvidenceWrite {
		return releasequery.NewCatalogAuthorizer().Authorize(ctx, a, request)
	}
	auth, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, request)
}
func (f postgresReleaseSetupFixture) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		out, err = r.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}
func (f postgresReleaseSetupFixture) LockCatalogCreationTenant(ctx context.Context, tenant string) error {
	return f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		return r.LockCatalogCreationTenant(ctx, tenant)
	})
}
func (f postgresReleaseSetupFixture) ProductSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	var found bool
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		found, err = r.ProductSlugExists(ctx, tenant, slug)
		return err
	})
	return found && err == nil, err
}
func (f postgresReleaseSetupFixture) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	var out releaseapp.ProductCoordinates
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		out, err = r.ReadProductCoordinates(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.ProductCoordinates{}, err
	}
	return out, nil
}
func (f postgresReleaseSetupFixture) ReadCatalogCreationProduct(ctx context.Context, tenant, id string) (releaseapp.CatalogCreationProduct, error) {
	var out releaseapp.CatalogCreationProduct
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		out, err = r.ReadCatalogCreationProduct(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	return out, nil
}
func (f postgresReleaseSetupFixture) ReleaseVersionExists(ctx context.Context, tenant, product, version string) (bool, error) {
	var found bool
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		found, err = r.ReleaseVersionExists(ctx, tenant, product, version)
		return err
	})
	return found && err == nil, err
}
func (f postgresReleaseSetupFixture) ArtifactIdentityByDigest(ctx context.Context, tenant, digest string) (releaseapp.ArtifactRegistrationIdentity, bool, error) {
	var out releaseapp.ArtifactRegistrationIdentity
	var found bool
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		out, found, err = r.ArtifactIdentityByDigest(ctx, tenant, digest)
		return err
	})
	if err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	return out, found, nil
}
func (f postgresReleaseSetupFixture) ReadArtifactMetadata(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	var out releasedomain.Artifact
	err := f.read(ctx, func(ctx context.Context, _ app.Repositories, r postgresReleaseFixtureFacts) error {
		var err error
		out, err = r.ReadArtifactMetadata(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f postgresReleaseSetupFixture) transaction(ctx context.Context, run func(context.Context, postgresReleaseSetupFixture) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories, _ postgresReleaseFixtureFacts) error {
		bound := f
		bound.repos = &r
		return run(ctx, bound)
	})
}
func (f postgresReleaseSetupFixture) ExecuteProduct(ctx context.Context, run func(context.Context, releaseapp.ProductTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx postgresReleaseSetupFixture) error { return run(ctx, tx) })
}
func (f postgresReleaseSetupFixture) ExecuteReleaseCreation(ctx context.Context, run func(context.Context, releaseapp.ReleaseCreationTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx postgresReleaseSetupFixture) error { return run(ctx, tx) })
}
func (f postgresReleaseSetupFixture) ExecuteArtifact(ctx context.Context, run func(context.Context, releaseapp.ArtifactTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx postgresReleaseSetupFixture) error { return run(ctx, tx) })
}
func (f postgresReleaseSetupFixture) InsertProduct(ctx context.Context, v releasedomain.Product) error {
	return postgresReleaseFixtureError(f.repos.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, CreatedAt: v.CreatedAt}))
}
func (f postgresReleaseSetupFixture) InsertRelease(ctx context.Context, v releasedomain.Release) error {
	return postgresReleaseFixtureError(f.repos.ReleaseCatalog.InsertRelease(ctx, domain.ReleaseFromContextModel(v)))
}
func (f postgresReleaseSetupFixture) InsertArtifact(ctx context.Context, v releasedomain.Artifact) error {
	return postgresReleaseFixtureError(f.repos.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: v.ID, TenantID: v.TenantID, Name: v.Name, MediaType: v.MediaType, Digest: v.Digest, Size: v.Size, CreatedAt: v.CreatedAt}))
}
func (f postgresReleaseSetupFixture) AuthorizeExisting(ctx context.Context, a domain.Actor, id string) error {
	return f.Authorize(ctx, a, application.AuthorizationRequest{Scope: releaseapp.ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: id}})
}
func (f postgresReleaseSetupFixture) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (postgresRedactionFixtureTransaction{audit: f.repos.Audit}).AppendAudit(ctx, e)
	return v, postgresReleaseFixtureError(err)
}
func (f postgresReleaseSetupFixture) clock() application.Clock {
	return application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
}
func (f postgresReleaseSetupFixture) CreateProduct(ctx context.Context, a domain.Actor, name, slug string) (domain.Product, error) {
	c, err := releaseapp.NewProductCommands(releaseapp.ProductCommandConfig{Transactions: f, Authorizer: f, Clock: f.clock(), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.Product{}, err
	}
	v, err := c.CreateProduct(ctx, a, releaseapp.CreateProductInput{Name: name, Slug: slug})
	return domain.Product{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, CreatedAt: v.CreatedAt}, err
}
func (f postgresReleaseSetupFixture) CreateRelease(ctx context.Context, a domain.Actor, product, version string) (domain.Release, error) {
	c, err := releaseapp.NewReleaseCommands(releaseapp.ReleaseCommandConfig{Transactions: f, Reader: f, Authorizer: f, Clock: f.clock(), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.Release{}, err
	}
	v, err := c.CreateRelease(ctx, a, releaseapp.CreateReleaseInput{ProductID: product, Version: version})
	return domain.ReleaseFromContextModel(v), err
}
func (f postgresReleaseSetupFixture) RegisterArtifact(ctx context.Context, a domain.Actor, name, media, digest string, size int64) (domain.Artifact, error) {
	c, err := releaseapp.NewArtifactCommands(releaseapp.ArtifactCommandConfig{Transactions: f, Authorizer: f, Clock: f.clock(), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.Artifact{}, err
	}
	v, err := c.RegisterArtifact(ctx, a, releaseapp.RegisterArtifactInput{Name: name, MediaType: media, Digest: digest, Size: size})
	return domain.Artifact{ID: v.ID, TenantID: v.TenantID, Name: v.Name, MediaType: v.MediaType, Digest: v.Digest, Size: v.Size, CreatedAt: v.CreatedAt}, err
}
