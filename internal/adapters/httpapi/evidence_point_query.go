package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func mapEvidencePointQueryError(err error) error {
	switch {
	case errors.Is(err, evidencequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, evidencequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, evidencequery.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
