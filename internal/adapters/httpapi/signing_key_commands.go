package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func mapSigningKeyCommandError(err error) error {
	switch {
	case errors.Is(err, verificationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, verificationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, verificationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
