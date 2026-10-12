package app

import (
	"errors"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Pure error translation still used by scoped repository helpers. No command
// service, aggregate state or runtime wiring lives here.
func fromPackageContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, packageapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, packageapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, packageapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, packageapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
