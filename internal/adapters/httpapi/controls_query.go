package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func controlFrameworkFromQuery(value riskdomain.ControlFramework) domain.ControlFramework {
	return domain.ControlFramework{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name,
		Slug: value.Slug, Version: value.Version, Description: value.Description,
		Status: value.Status, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func securityControlFromQuery(value riskdomain.SecurityControl) domain.SecurityControl {
	requirements := make([]domain.ControlEvidenceRequirement, 0, len(value.EvidenceRequirements))
	for _, requirement := range value.EvidenceRequirements {
		requirements = append(requirements, domain.ControlEvidenceRequirement{
			Type: requirement.Type, FreshnessDays: requirement.FreshnessDays, Required: requirement.Required,
		})
	}
	return domain.SecurityControl{
		ID: value.ID, TenantID: value.TenantID, FrameworkID: value.FrameworkID,
		Code: value.Code, Title: value.Title, Objective: value.Objective,
		EvidenceRequirements: requirements, Applicability: value.Applicability,
		Limitations: value.Limitations, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt,
	}
}

func mapControlsQueryError(err error) error {
	switch {
	case errors.Is(err, riskquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, riskquery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, riskquery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
