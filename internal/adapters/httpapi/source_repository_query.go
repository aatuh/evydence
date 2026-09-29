package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func sourceRepositoryFromQuery(item integrationdomain.SourceRepository) domain.SourceRepository {
	return domain.SourceRepository{
		ID: item.ID, TenantID: item.TenantID, ProjectID: item.ProjectID,
		Provider: item.Provider, FullName: item.FullName, CloneURL: item.CloneURL,
		DefaultBranch: item.DefaultBranch, SchemaVersion: item.SchemaVersion, CreatedAt: item.CreatedAt,
	}
}

func mapSourceRepositoryQueryError(err error) error {
	switch {
	case errors.Is(err, integrationquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, integrationquery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
