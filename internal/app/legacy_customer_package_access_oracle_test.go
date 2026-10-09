package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged aggregate behavior is retained only as a characterization oracle.
func (l *Ledger) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
	value, err := l.packageCommands.AccessCustomerSecurityPackage(ctx, actor, id)
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}

func (l *Ledger) ExportCustomerSecurityPackageArchive(ctx context.Context, actor domain.Actor, id string) (CustomerPackageArchive, error) {
	pkg, err := l.AccessCustomerSecurityPackage(ctx, actor, id)
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func (l *Ledger) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
	report, err := l.packageCommands.SecurityReviewPackageReport(ctx, actor, packageID)
	if err != nil {
		return domain.SecurityReviewPackageReport{}, fromPackageContextError(err)
	}
	return domain.SecurityReviewPackageReport{ReportType: report.ReportType, TemplateVersion: report.TemplateVersion, PackageID: report.PackageID, ProductID: report.ProductID, ReleaseID: report.ReleaseID, EvidenceIDs: report.EvidenceIDs, Assumptions: report.Assumptions, Limitations: report.Limitations, GeneratedAt: report.GeneratedAt}, nil
}
