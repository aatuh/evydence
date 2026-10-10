package app

import (
	"errors"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Pure DTO/error translations still used by scoped repository and projection
// helpers. No command service, aggregate state or runtime wiring lives here.
func redactionProfileToPackageContext(value domain.RedactionProfile) packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Description: value.Description,
		AllowedTypes: append([]string(nil), value.AllowedTypes...), ExcludedFields: append([]string(nil), value.ExcludedFields...),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func fromPackageContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, packageapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, packageapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, packageapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, packageapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
