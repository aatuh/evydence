package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func mapSigningCustodyQueryError(err error) error {
	switch {
	case errors.Is(err, verificationquery.ErrSigningCustodyValidation), errors.Is(err, verificationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, verificationquery.ErrSigningCustodyProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
