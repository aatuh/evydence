package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func mapSourceRepositoryCommandError(err error) error {
	switch {
	case errors.Is(err, integrationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, integrationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, integrationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
