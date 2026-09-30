package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildProjectCommands binds parent reads and transactional writes to focused
// ports. The reader must scope the parent by tenant before returning it.
func BuildProjectCommands(reader releaseapp.ProjectReader, factory app.UnitOfWorkFactory) (*releaseapp.ProjectCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("project reader and transactions are required")
	}
	return releaseapp.NewProjectCommands(releaseapp.ProjectCommandConfig{
		Reader:       catalogParentReader{source: reader},
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: catalogTransactions{factory: factory},
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type catalogParentReader struct{ source releaseapp.ProjectReader }

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
