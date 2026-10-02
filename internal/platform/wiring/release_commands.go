package wiring

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildReleaseCommands uses current bounded product coordinates and a boolean
// version lookup, without pool metadata reads or cached Ledger releases.
func BuildReleaseCommands(factory app.UnitOfWorkFactory) (*releaseapp.ReleaseCommands, error) {
	if factory == nil {
		return nil, errors.New("release transactions are required")
	}
	return releaseapp.NewReleaseCommands(releaseapp.ReleaseCommandConfig{
		Reader:       catalogProductReads{factory: factory},
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: releaseCreationCommandTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type releaseCreationCommandTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseCreationCommandTransactions) ExecuteReleaseCreation(ctx context.Context, fn func(context.Context, releaseapp.ReleaseCreationTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		parent, ok := repos.ReleaseCatalog.(releaseapp.ProductCoordinateReader)
		versions, valid := repos.ReleaseCatalog.(releaseapp.ReleaseVersionReader)
		if !ok || !valid || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, releaseCreationCommandTransaction{parent: parent, versions: versions, writer: repos.ReleaseCatalog, audit: repos.Audit})
	}))
}

type releaseCreationCommandTransaction struct {
	parent   releaseapp.ProductCoordinateReader
	versions releaseapp.ReleaseVersionReader
	writer   interface {
		InsertRelease(context.Context, domain.Release) error
	}
	audit app.AuditRepository
}

func (t releaseCreationCommandTransaction) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	v, err := t.parent.ReadProductCoordinates(ctx, tenant, id)
	if err != nil {
		return releaseapp.ProductCoordinates{}, mapProductWriteError(err)
	}
	return v, nil
}

func (t releaseCreationCommandTransaction) ReleaseVersionExists(ctx context.Context, tenant, product, version string) (bool, error) {
	if version == "" || len(version) > 65536 || !utf8.ValidString(version) || strings.ContainsRune(version, 0) {
		return false, releaseapp.ErrValidation
	}
	v, err := t.versions.ReleaseVersionExists(ctx, tenant, product, version)
	return v, mapProductWriteError(err)
}

func (t releaseCreationCommandTransaction) InsertRelease(ctx context.Context, v releasedomain.Release) error {
	for _, text := range []string{v.ID, v.TenantID, v.ProductID} {
		if text == "" || len(text) > 1024 || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return releaseapp.ErrValidation
		}
	}
	return mapProductWriteError(t.writer.InsertRelease(ctx, domain.Release{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Version: v.Version, State: v.State.String(), Revision: v.Revision, CreatedAt: v.CreatedAt, FrozenAt: v.FrozenAt, ApprovedAt: v.ApprovedAt}))
}

func (t releaseCreationCommandTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}
