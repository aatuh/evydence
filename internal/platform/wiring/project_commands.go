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
		Reader:       projectParentReads{factory: factory},
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: projectTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type projectParentReads struct{ factory app.UnitOfWorkFactory }

func (r projectParentReads) ReadProjectProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProjectProductCoordinates, error) {
	var v releaseapp.ProjectProductCoordinates
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.ProjectReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		v, err = reader.ReadProjectProductCoordinates(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.ProjectProductCoordinates{}, mapProductWriteError(err)
	}
	return v, nil
}

type projectTransactions struct{ factory app.UnitOfWorkFactory }

func (t projectTransactions) ExecuteProject(ctx context.Context, fn func(context.Context, releaseapp.ProjectTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.ProjectReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, projectTransaction{reader: reader, writer: repos.ReleaseCatalog, audit: repos.Audit})
	}))
}

type projectTransaction struct {
	reader releaseapp.ProjectReader
	writer interface {
		InsertProject(context.Context, domain.Project) error
	}
	audit app.AuditRepository
}

func (t projectTransaction) ReadProjectProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProjectProductCoordinates, error) {
	v, err := t.reader.ReadProjectProductCoordinates(ctx, tenant, id)
	if err != nil {
		return releaseapp.ProjectProductCoordinates{}, mapProductWriteError(err)
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

// This reader remains only for the not-yet-migrated release-create builder.
type catalogParentReader struct{ source releaseapp.ReleaseReader }

func (r catalogParentReader) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	product, err := r.source.GetProduct(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Product{}, mapProjectReadError(err)
	}
	return product, nil
}

func mapProjectReadError(err error) error {
	switch {
	case errors.Is(err, releasequery.ErrNotFound):
		return releaseapp.ErrNotFound
	case errors.Is(err, releasequery.ErrValidation):
		return releaseapp.ErrValidation
	default:
		return mapProductWriteError(err)
	}
}
