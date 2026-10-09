package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func mapMissingEvidenceQueryError(err error) error {
	switch {
	case errors.Is(err, riskquery.ErrValidation), errors.Is(err, packagequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, riskquery.ErrNotFound), errors.Is(err, riskapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, riskquery.ErrInvalidProjection), errors.Is(err, packagequery.ErrInvalidProjection), errors.Is(err, riskapp.ErrValidation):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
