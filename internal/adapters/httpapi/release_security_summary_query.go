package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func mapReleaseSecuritySummaryQueryError(err error) error {
	switch {
	case errors.Is(err, riskquery.ErrValidation):
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

func releaseSecuritySummaryFromQuery(value riskdomain.ReleaseSecuritySummary) domain.ReleaseSecuritySummary {
	missing := make([]domain.ReleaseSecurityMissingDecision, 0, len(value.MissingRequiredDecisions))
	for _, item := range value.MissingRequiredDecisions {
		missing = append(missing, domain.ReleaseSecurityMissingDecision{
			FindingID: item.FindingID, ScanID: item.ScanID, Vulnerability: item.Vulnerability,
			Component: item.Component, Severity: item.Severity, State: item.State,
		})
	}
	return domain.ReleaseSecuritySummary{
		Product:       domain.ReleaseSecurityProductSummary{ID: value.Product.ID, Name: value.Product.Name, Slug: value.Product.Slug},
		Release:       domain.ReleaseSecurityReleaseSummary{ID: value.Release.ID, Version: value.Release.Version, State: value.Release.State},
		ArtifactCount: value.ArtifactCount, SBOMStatus: value.SBOMStatus, VulnerabilityScanStatus: value.VulnerabilityScanStatus,
		OpenFindingsBySeverity: value.OpenFindingsBySeverity, DecisionsByStatus: value.DecisionsByStatus,
		MissingRequiredDecisions: missing,
		ApprovalSummary:          domain.ReleaseSecurityApprovalSummary{Total: value.ApprovalSummary.Total, Approved: value.ApprovalSummary.Approved},
		ExceptionSummary: domain.ReleaseSecurityExceptionSummary{
			Total: value.ExceptionSummary.Total, ApprovedUnexpired: value.ExceptionSummary.ApprovedUnexpired,
			Unapproved: value.ExceptionSummary.Unapproved, Expired: value.ExceptionSummary.Expired,
		},
		ReadinessStatus: value.ReadinessStatus, PackageStatus: value.PackageStatus, Counts: value.Counts,
		Assumptions: value.Assumptions, Limitations: value.Limitations,
		SchemaVersion: value.SchemaVersion, GeneratedAt: value.GeneratedAt,
	}
}
