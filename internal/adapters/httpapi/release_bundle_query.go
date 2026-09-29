package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func releaseBundleFromQuery(bundle packagedomain.ReleaseBundle) domain.ReleaseBundle {
	return domain.ReleaseBundle{
		ID: bundle.ID, TenantID: bundle.TenantID, ReleaseID: bundle.ReleaseID,
		State: bundle.State.String(), Manifest: bundle.Manifest,
		ManifestHash: bundle.ManifestHash, SignatureRefs: bundle.SignatureRefs,
		CreatedAt: bundle.CreatedAt, PublishedAt: bundle.PublishedAt, RevokedAt: bundle.RevokedAt,
	}
}

func mapReleaseBundleQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrReleaseBundleNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrReleaseBundleProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
