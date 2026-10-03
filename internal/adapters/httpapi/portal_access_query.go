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

func portalAccessFromQuery(access packagedomain.CustomerPortalAccess) domain.CustomerPortalAccess {
	return domain.CustomerPortalAccess{
		ID: access.ID, TenantID: access.TenantID, PackageID: access.PackageID,
		CustomerName: access.CustomerName, ReviewerName: access.ReviewerName,
		ReviewerEmail: access.ReviewerEmail, RequireNDA: access.RequireNDA,
		NDAAcceptedAt: access.NDAAcceptedAt, NDAAcceptedBy: access.NDAAcceptedBy,
		Watermark: access.Watermark, Prefix: access.Prefix, ExpiresAt: access.ExpiresAt,
		RevokedAt: access.RevokedAt, AccessCount: access.AccessCount,
		FailedAccessCount: access.FailedAccessCount, LastAccessedAt: access.LastAccessedAt,
		LastFailedAt: access.LastFailedAt, SchemaVersion: access.SchemaVersion,
		CreatedAt: access.CreatedAt,
	}
}

func mapPortalAccessQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrPortalAccessValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrPortalAccessNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrPortalAccessProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
