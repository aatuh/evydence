package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func artifactFromQuery(value releasedomain.Artifact) domain.Artifact {
	return domain.Artifact{ID: value.ID, TenantID: value.TenantID, Name: value.Name,
		MediaType: value.MediaType, Size: value.Size, Digest: value.Digest, CreatedAt: value.CreatedAt}
}

func mapArtifactPointQueryError(err error) error {
	switch {
	case errors.Is(err, releasequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, releasequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, releasequery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
