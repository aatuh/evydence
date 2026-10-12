package httpapi

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

type catalogCreationFixtureFacts interface {
	releaseapp.CatalogCreationGuardReader
	releaseapp.ProductSlugReader
	releaseapp.ProductCoordinateReader
	releaseapp.ReleaseVersionReader
}
type catalogCreationNativeFixture struct {
	catalogFixtureCommands
	repositories *app.Repositories
	readOnly     bool
}

func releaseFixtureCoreError(err error) error {
	if revision, ok := app.CurrentRevision(err); ok {
		return releaseapp.NewVersionConflict(revision)
	}
	switch {
	case errors.Is(err, app.ErrValidation) || errors.Is(err, releasequery.ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, app.ErrNotFound) || errors.Is(err, releasequery.ErrNotFound):
		return releaseapp.ErrNotFound
	case errors.Is(err, app.ErrForbidden):
		return releaseapp.ErrForbidden
	case errors.Is(err, app.ErrConflict) || errors.Is(err, releasequery.ErrInvalidProjection):
		return releaseapp.ErrConflict
	default:
		return err
	}
}
func (f catalogCreationNativeFixture) read(ctx context.Context, run func(context.Context, app.Repositories) error) error {
	if ctx == nil || run == nil {
		return releaseapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.repositories != nil {
		return releaseFixtureCoreError(run(ctx, *f.repositories))
	}
	return releaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, run))
}
func (f catalogCreationNativeFixture) facts(ctx context.Context, run func(context.Context, catalogCreationFixtureFacts) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.ReleaseCatalog.(catalogCreationFixtureFacts)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	})
}
func (f catalogCreationNativeFixture) Authorize(ctx context.Context, actor domain.Actor, r application.AuthorizationRequest) error {
	return releasequery.NewCatalogAuthorizer().Authorize(ctx, actor, r)
}
func (f catalogCreationNativeFixture) LockCatalogCreationTenant(ctx context.Context, tenant string) error {
	return f.facts(ctx, func(ctx context.Context, r catalogCreationFixtureFacts) error {
		return r.LockCatalogCreationTenant(ctx, tenant)
	})
}
func (f catalogCreationNativeFixture) ReadCatalogCreationProduct(ctx context.Context, tenant, id string) (releaseapp.CatalogCreationProduct, error) {
	var v releaseapp.CatalogCreationProduct
	err := f.facts(ctx, func(ctx context.Context, r catalogCreationFixtureFacts) error {
		var err error
		v, err = r.ReadCatalogCreationProduct(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	return v, nil
}
func (f catalogCreationNativeFixture) ProductSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	if f.readOnly {
		panic("catalog replay inspected product uniqueness")
	}
	var v bool
	err := f.facts(ctx, func(ctx context.Context, r catalogCreationFixtureFacts) error {
		var err error
		v, err = r.ProductSlugExists(ctx, tenant, slug)
		return err
	})
	return v && err == nil, err
}
func (f catalogCreationNativeFixture) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	if f.readOnly {
		panic("catalog replay inspected product slug")
	}
	var v releaseapp.ProductCoordinates
	err := f.facts(ctx, func(ctx context.Context, r catalogCreationFixtureFacts) error {
		var err error
		v, err = r.ReadProductCoordinates(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.ProductCoordinates{}, err
	}
	return v, nil
}
func (f catalogCreationNativeFixture) ReleaseVersionExists(ctx context.Context, tenant, product, version string) (bool, error) {
	if f.readOnly {
		panic("catalog replay inspected release uniqueness")
	}
	var v bool
	err := f.facts(ctx, func(ctx context.Context, r catalogCreationFixtureFacts) error {
		var err error
		v, err = r.ReleaseVersionExists(ctx, tenant, product, version)
		return err
	})
	return v && err == nil, err
}
func (f catalogCreationNativeFixture) transaction(ctx context.Context, run func(context.Context, catalogCreationNativeFixture) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		if _, ok := r.ReleaseCatalog.(catalogCreationFixtureFacts); !ok || r.Audit == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	})
}
func (f catalogCreationNativeFixture) ExecuteProduct(ctx context.Context, run func(context.Context, releaseapp.ProductTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx catalogCreationNativeFixture) error { return run(ctx, tx) })
}
func (f catalogCreationNativeFixture) ExecuteProject(ctx context.Context, run func(context.Context, releaseapp.ProjectTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx catalogCreationNativeFixture) error { return run(ctx, tx) })
}
func (f catalogCreationNativeFixture) ExecuteReleaseCreation(ctx context.Context, run func(context.Context, releaseapp.ReleaseCreationTransaction) error) error {
	return f.transaction(ctx, func(ctx context.Context, tx catalogCreationNativeFixture) error { return run(ctx, tx) })
}
func (f catalogCreationNativeFixture) InsertProduct(ctx context.Context, v releasedomain.Product) error {
	if f.readOnly || f.repositories == nil {
		panic("catalog preflight/unbound product write")
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, CreatedAt: v.CreatedAt}))
}
func (f catalogCreationNativeFixture) InsertProject(ctx context.Context, v releasedomain.Project) error {
	if f.readOnly || f.repositories == nil {
		panic("catalog preflight/unbound project write")
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.InsertProject(ctx, domain.Project{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, CreatedAt: v.CreatedAt}))
}
func (f catalogCreationNativeFixture) InsertRelease(ctx context.Context, v releasedomain.Release) error {
	if f.readOnly || f.repositories == nil {
		panic("catalog preflight/unbound release write")
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.InsertRelease(ctx, domain.ReleaseFromContextModel(v)))
}
func (f catalogCreationNativeFixture) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.readOnly || f.repositories == nil {
		panic("catalog preflight/unbound audit write")
	}
	v, err := (governanceFixtureTransaction{audit: f.repositories.Audit}).AppendAudit(ctx, e)
	return v, releaseFixtureCoreError(err)
}
func (f catalogFixtureCommands) nativeCatalog(readOnly bool) (catalogCreationNativeFixture, application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly {
		clock = application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	}
	return catalogCreationNativeFixture{catalogFixtureCommands: f, readOnly: readOnly}, clock, ids
}
func (f catalogFixtureCommands) nativeProduct(readOnly bool) (*releaseapp.ProductCommands, error) {
	ports, clock, ids := f.nativeCatalog(readOnly)
	return releaseapp.NewProductCommands(releaseapp.ProductCommandConfig{Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
func (f catalogFixtureCommands) nativeProject(readOnly bool) (*releaseapp.ProjectCommands, error) {
	ports, clock, ids := f.nativeCatalog(readOnly)
	return releaseapp.NewProjectCommands(releaseapp.ProjectCommandConfig{Reader: ports, Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
func (f catalogFixtureCommands) nativeRelease(readOnly bool) (*releaseapp.ReleaseCommands, error) {
	ports, clock, ids := f.nativeCatalog(readOnly)
	return releaseapp.NewReleaseCommands(releaseapp.ReleaseCommandConfig{Reader: ports, Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
