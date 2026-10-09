package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func answerLibraryEntryFromQuery(entry packagedomain.QuestionnaireAnswerLibraryEntry) domain.QuestionnaireAnswerLibraryEntry {
	return domain.QuestionnaireAnswerLibraryEntry{
		ID: entry.ID, TenantID: entry.TenantID, QuestionID: entry.QuestionID,
		EvidenceType: entry.EvidenceType, ControlID: entry.ControlID,
		ProductID: entry.ProductID, ReleaseID: entry.ReleaseID, Answer: entry.Answer,
		EvidenceIDs: entry.EvidenceIDs, Limitations: entry.Limitations,
		SchemaVersion: entry.SchemaVersion, CreatedAt: entry.CreatedAt,
	}
}

func mapAnswerLibraryQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
