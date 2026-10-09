package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func fixtureIngestionError(err error) error {
	if errors.Is(err, app.ErrForbidden) {
		return application.ErrForbidden
	}
	if errors.Is(err, app.ErrNotFound) || errors.Is(err, evidencequery.ErrNotFound) {
		return evidenceapp.ErrNotFound
	}
	if errors.Is(err, app.ErrValidation) || errors.Is(err, evidencequery.ErrValidation) {
		return evidenceapp.ErrValidation
	}
	if errors.Is(err, app.ErrConflict) || errors.Is(err, evidencequery.ErrConflict) {
		return evidenceapp.ErrConflict
	}
	return err
}
