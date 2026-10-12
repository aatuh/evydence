package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func commercialCollectorFromQuery(definition integrationdomain.CommercialCollectorDefinition) domain.CommercialCollectorDefinition {
	return domain.CommercialCollectorDefinition{
		ID: definition.ID, TenantID: definition.TenantID, Name: definition.Name,
		Provider: definition.Provider, Version: definition.Version,
		ManifestHash: definition.ManifestHash, AllowedScopes: definition.AllowedScopes,
		Status: definition.Status, SchemaVersion: definition.SchemaVersion,
		CreatedAt: definition.CreatedAt,
	}
}

func mapCommercialCollectorQueryError(err error) error {
	switch {
	case errors.Is(err, integrationquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, integrationquery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
