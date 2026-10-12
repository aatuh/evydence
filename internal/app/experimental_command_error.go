package app

import (
	"errors"

	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
)

func fromExperimentalCommandError(err error) error {
	switch {
	case errors.Is(err, experimentalapp.ErrVerificationFailed):
		return ErrVerificationFailed
	case errors.Is(err, experimentalapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, experimentalapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, experimentalapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return ErrForbidden
	default:
		return err
	}
}
