package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Authentication is owned by the handler; the focused command resolves scope,
// expiry and committed access auditing. Rendering only consumes that frozen
// result, using the same bounded utility as the portal download path.
func (s *Server) customerPackageArchive(ctx context.Context, actor domain.Actor, id string) (app.CustomerPackageArchive, error) {
	pkg, err := s.customerPackageAccessCommands.AccessCustomerSecurityPackage(ctx, actor, id)
	if err != nil {
		return app.CustomerPackageArchive{}, mapCustomerPackageAccessError(err)
	}
	return app.RenderCustomerPackageArchive(customerPackageFromAccess(pkg))
}

func mapCustomerPackageAccessError(err error) error {
	switch {
	case errors.Is(err, packageapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, packageapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, packageapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

func customerPackageFromAccess(pkg packagedomain.CustomerSecurityPackage) domain.CustomerSecurityPackage {
	return domain.CustomerSecurityPackage{ID: pkg.ID, TenantID: pkg.TenantID, ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, RedactionProfileID: pkg.RedactionProfileID, Title: pkg.Title, State: pkg.State, Manifest: pkg.Manifest, ManifestHash: pkg.ManifestHash, DistributionWatermark: pkg.DistributionWatermark, ExpiresAt: pkg.ExpiresAt, AccessCount: pkg.AccessCount, SchemaVersion: pkg.SchemaVersion, CreatedAt: pkg.CreatedAt}
}

func securityReviewPackageFromAccess(report packagedomain.SecurityReviewPackageReport) domain.SecurityReviewPackageReport {
	return domain.SecurityReviewPackageReport{ReportType: report.ReportType, TemplateVersion: report.TemplateVersion, PackageID: report.PackageID, ProductID: report.ProductID, ReleaseID: report.ReleaseID, EvidenceIDs: report.EvidenceIDs, Assumptions: report.Assumptions, Limitations: report.Limitations, GeneratedAt: report.GeneratedAt}
}
