package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildReleaseStateCommands composes release transitions against current
// tenant-owned rows. A row lock keeps competing transitions ordered while the
// state update and audit entry commit in one unit of work.
func BuildReleaseStateCommands(factory app.UnitOfWorkFactory) (*releaseapp.ReleaseStateCommands, error) {
	if factory == nil {
		return nil, errors.New("release state transactions are required")
	}
	return releaseapp.NewReleaseStateCommands(releaseapp.ReleaseStateCommandConfig{
		Reader: releaseStateParentReader{catalogProductReads: catalogProductReads{factory: factory}}, Authorizer: releasequery.NewCatalogAuthorizer(),
		Transactions: releaseStateCommandTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type releaseStateParentReader struct{ catalogProductReads }

func (r releaseStateParentReader) ReadReleaseState(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	var v releasedomain.Release
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.ReleaseStateReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		v, err = reader.ReadReleaseState(ctx, tenantID, id)
		return err
	})
	if err != nil {
		return releasedomain.Release{}, mapReleaseStateWriteError(err)
	}
	return v, nil
}

type releaseStateCommandTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseStateCommandTransactions) ExecuteReleaseState(ctx context.Context, command func(context.Context, releaseapp.ReleaseStateTransaction) error) error {
	return mapReleaseStateWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		reader, ok := repositories.ReleaseCatalog.(releaseapp.ReleaseStateReader)
		if !ok || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, releaseStateCommandTransaction{reader: reader, writer: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

type releaseStateCommandTransaction struct {
	reader releaseapp.ReleaseStateReader
	writer interface {
		UpdateReleaseState(context.Context, domain.Release, string) error
	}
	audit app.AuditRepository
}

func (t releaseStateCommandTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return releasequery.NewCatalogAuthorizer().Authorize(ctx, actor, request)
}

func (t releaseStateCommandTransaction) ReadReleaseState(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := t.reader.ReadReleaseState(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Release{}, mapReleaseStateWriteError(err)
	}
	return release, nil
}

func (t releaseStateCommandTransaction) ReadProductCoordinates(ctx context.Context, tenantID, id string) (releaseapp.ProductCoordinates, error) {
	v, err := t.reader.ReadProductCoordinates(ctx, tenantID, id)
	if err != nil {
		return releaseapp.ProductCoordinates{}, mapReleaseStateWriteError(err)
	}
	return v, nil
}

func (t releaseStateCommandTransaction) UpdateRelease(ctx context.Context, release releasedomain.Release, expectedRevision int64, expectedState string) error {
	if release.Revision != expectedRevision+1 {
		return releaseapp.ErrConflict
	}
	return mapReleaseStateWriteError(t.writer.UpdateReleaseState(ctx, domain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, State: release.State.String(), Revision: release.Revision,
		FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt, CreatedAt: release.CreatedAt,
	}, expectedState))
}

func (t releaseStateCommandTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
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
