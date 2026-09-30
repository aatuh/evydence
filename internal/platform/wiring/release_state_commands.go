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

// BuildReleaseStateCommands composes release transitions against current
// tenant-owned rows. A row lock keeps competing transitions ordered while the
// state update and audit entry commit in one unit of work.
func BuildReleaseStateCommands(reader releaseapp.ReleaseStateReader, factory app.UnitOfWorkFactory) (*releaseapp.ReleaseStateCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("release state reader and transactions are required")
	}
	return releaseapp.NewReleaseStateCommands(releaseapp.ReleaseStateCommandConfig{
		Reader: releaseStateParentReader{source: reader}, Authorizer: releasequery.NewCatalogAuthorizer(),
		Transactions: releaseStateCommandTransactions{factory: factory},
		Clock:        application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type releaseStateParentReader struct{ source releaseapp.ReleaseStateReader }

func (r releaseStateParentReader) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	product, err := r.source.GetProduct(ctx, tenantID, id)
	return product, mapProjectReadError(err)
}

func (r releaseStateParentReader) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := r.source.GetRelease(ctx, tenantID, id)
	return release, mapProjectReadError(err)
}

type releaseStateCommandTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseStateCommandTransactions) ExecuteReleaseState(ctx context.Context, command func(context.Context, releaseapp.ReleaseStateTransaction) error) error {
	return mapReleaseStateWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, releaseStateCommandTransaction{catalog: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

type releaseStateCommandTransaction struct {
	catalog app.ReleaseCatalogRepository
	audit   app.AuditRepository
}

func (t releaseStateCommandTransaction) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := t.catalog.GetReleaseForUpdate(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Release{}, mapReleaseStateWriteError(err)
	}
	return releaseFromCatalogRow(release)
}

func (t releaseStateCommandTransaction) UpdateRelease(ctx context.Context, release releasedomain.Release, expectedRevision int64, expectedState string) error {
	if release.Revision != expectedRevision+1 {
		return releaseapp.ErrConflict
	}
	return mapReleaseStateWriteError(t.catalog.UpdateReleaseState(ctx, domain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, State: release.State.String(), Revision: release.Revision,
		FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt, CreatedAt: release.CreatedAt,
	}, expectedState))
}

func (t releaseStateCommandTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction(t).AppendAudit(ctx, event)
}

func releaseFromCatalogRow(release domain.Release) (releasedomain.Release, error) {
	state, err := releasedomain.ParseReleaseState(release.State)
	if err != nil {
		return releasedomain.Release{}, releaseapp.ErrValidation
	}
	return releasedomain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, State: state, Revision: release.Revision,
		FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt, CreatedAt: release.CreatedAt,
	}, nil
}

func mapReleaseStateWriteError(err error) error {
	if revision, ok := app.CurrentRevision(err); ok {
		return releaseapp.NewVersionConflict(revision)
	}
	return mapProductWriteError(err)
}
