package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// EvidenceCreationCommands does not expose parsers, lifecycle mutations or
// unrelated queries to the generic evidence creation handler.
type EvidenceCreationCommands interface {
	CreateEvidence(context.Context, identitydomain.Actor, evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error)
}

func mapEvidenceCreationCommandError(err error) error {
	switch {
	case errors.Is(err, evidenceapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, evidenceapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, evidenceapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
