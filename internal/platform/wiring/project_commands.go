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

// BuildProjectCommands binds bounded parent coordinates and all writes to the
// current unit of work. No pool reader or Ledger product metadata is used.
func BuildProjectCommands(factory app.UnitOfWorkFactory) (*releaseapp.ProjectCommands, error) {
	if factory == nil {
		return nil, errors.New("project transactions are required")
	}
	return releaseapp.NewProjectCommands(releaseapp.ProjectCommandConfig{
		Reader:       catalogProductReads{factory: factory},
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: projectTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type catalogProductReads struct{ factory app.UnitOfWorkFactory }

func (r catalogProductReads) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	var v releaseapp.ProductCoordinates
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.ProductCoordinateReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		v, err = reader.ReadProductCoordinates(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.ProductCoordinates{}, mapProductWriteError(err)
	}
	return v, nil
}

type projectTransactions struct{ factory app.UnitOfWorkFactory }

func (t projectTransactions) ExecuteProject(ctx context.Context, fn func(context.Context, releaseapp.ProjectTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.ProductCoordinateReader)
		guard, valid := repos.ReleaseCatalog.(releaseapp.CatalogCreationGuardReader)
		if !ok || !valid || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, projectTransaction{catalogCreationGuard: catalogCreationGuard{reader: guard}, reader: reader, writer: repos.ReleaseCatalog, audit: repos.Audit})
	}))
}

type projectTransaction struct {
	catalogCreationGuard
	reader releaseapp.ProductCoordinateReader
	writer interface {
		InsertProject(context.Context, domain.Project) error
	}
	audit app.AuditRepository
}

func (t projectTransaction) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	v, err := t.reader.ReadProductCoordinates(ctx, tenant, id)
	if err != nil {
		return releaseapp.ProductCoordinates{}, mapProductWriteError(err)
	}
	return v, nil
}

func (t projectTransaction) InsertProject(ctx context.Context, v releasedomain.Project) error {
	for _, field := range []struct {
		text  string
		limit int
	}{{v.ID, 1024}, {v.TenantID, 1024}, {v.ProductID, 1024}, {v.Name, 65536}} {
		if len(field.text) > field.limit || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return releaseapp.ErrValidation
		}
	}
	return mapProductWriteError(t.writer.InsertProject(ctx, domain.Project{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, CreatedAt: v.CreatedAt}))
}

func (t projectTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}
