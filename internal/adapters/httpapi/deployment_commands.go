package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func mapDeploymentCommandError(err error) error {
	switch {
	case errors.Is(err, operationsapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, operationsapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, operationsapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
