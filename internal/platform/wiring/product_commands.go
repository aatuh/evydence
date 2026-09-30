package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildProductCommands composes the release-owned product command directly on
// transaction-scoped repositories. It never constructs or loads a Ledger.
func BuildProductCommands(factory app.UnitOfWorkFactory) (*releaseapp.ProductCommands, error) {
	if factory == nil {
		return nil, errors.New("product transactions are required")
	}
	return releaseapp.NewProductCommands(releaseapp.ProductCommandConfig{
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: catalogTransactions{factory: factory},
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type catalogTransactions struct{ factory app.UnitOfWorkFactory }

func (t catalogTransactions) ExecuteProduct(ctx context.Context, command func(context.Context, releaseapp.ProductTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, catalogTransaction{catalog: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

func (t catalogTransactions) ExecuteProject(ctx context.Context, command func(context.Context, releaseapp.ProjectTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, catalogTransaction{catalog: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

func (t catalogTransactions) ExecuteReleaseCreation(ctx context.Context, command func(context.Context, releaseapp.ReleaseCreationTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, catalogTransaction{catalog: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

type catalogTransaction struct {
	catalog app.ReleaseCatalogRepository
	audit   app.AuditRepository
}

func (t catalogTransaction) ProductBySlug(ctx context.Context, tenantID, slug string) (releasedomain.Product, bool, error) {
	product, found, err := t.catalog.ProductBySlug(ctx, tenantID, slug)
	if err != nil {
		return releasedomain.Product{}, false, mapProductWriteError(err)
	}
	if !found {
		return releasedomain.Product{}, false, nil
	}
	return releasedomain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt}, true, nil
}

func (t catalogTransaction) InsertProduct(ctx context.Context, product releasedomain.Product) error {
	return mapProductWriteError(t.catalog.InsertProduct(ctx, domain.Product{
		ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt,
	}))
}

func (t catalogTransaction) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	product, err := t.catalog.GetProduct(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Product{}, mapProductWriteError(err)
	}
	return releasedomain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt}, nil
}

func (t catalogTransaction) InsertProject(ctx context.Context, project releasedomain.Project) error {
	return mapProductWriteError(t.catalog.InsertProject(ctx, domain.Project{
		ID: project.ID, TenantID: project.TenantID, ProductID: project.ProductID,
		Name: project.Name, CreatedAt: project.CreatedAt,
	}))
}

func (t catalogTransaction) ReleaseByVersion(ctx context.Context, tenantID, productID, version string) (releasedomain.Release, bool, error) {
	release, found, err := t.catalog.ReleaseByVersion(ctx, tenantID, productID, version)
	if err != nil {
		return releasedomain.Release{}, false, mapProductWriteError(err)
	}
	if !found {
		return releasedomain.Release{}, false, nil
	}
	state, err := releasedomain.ParseReleaseState(release.State)
	if err != nil {
		return releasedomain.Release{}, false, releaseapp.ErrValidation
	}
	return releasedomain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, Revision: release.Revision, State: state,
		CreatedAt: release.CreatedAt, FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt,
	}, true, nil
}

func (t catalogTransaction) InsertRelease(ctx context.Context, release releasedomain.Release) error {
	return mapProductWriteError(t.catalog.InsertRelease(ctx, domain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, Revision: release.Revision, State: release.State.String(),
		CreatedAt: release.CreatedAt, FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt,
	}))
}

func (t catalogTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry, err := t.audit.Append(ctx, domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType,
		SubjectType: event.SubjectType, SubjectID: event.SubjectID,
		ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef,
		SchemaVersion: domain.AuditChainEntrySchemaVersion,
	})
	if err != nil {
		return application.AuditReceipt{}, mapProductWriteError(err)
	}
	return application.AuditReceipt{ID: entry.ID}, nil
}

func mapProductWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, app.ErrConflict):
		return releaseapp.ErrConflict
	case errors.Is(err, app.ErrNotFound):
		return releaseapp.ErrNotFound
	default:
		return err
	}
}
