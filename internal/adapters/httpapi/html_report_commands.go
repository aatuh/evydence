package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func htmlReportFromCommands(report packagedomain.HTMLReportPackage) domain.HTMLReportPackage {
	return domain.HTMLReportPackage{ID: report.ID, TenantID: report.TenantID, ReportType: report.ReportType, ProductID: report.ProductID, ReleaseID: report.ReleaseID, HTML: report.HTML, Hash: report.Hash, SchemaVersion: report.SchemaVersion, CreatedAt: report.CreatedAt}
}
