package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.PDFReportReader = futureExtensions{}

func (r futureExtensions) ReadPDFReportScope(ctx context.Context, tenant, product, release string) (packageapp.PDFReportScope, error) {
	s, err := r.ReadGraphSnapshotScope(ctx, tenant, product, release)
	return packageapp.PDFReportScope{TenantID: s.TenantID, Resources: s.Resources}, err
}
func (r futureExtensions) InsertFocusedPDFReportPackage(ctx context.Context, v packagedomain.PDFReportPackage) error {
	if _, err := r.ReadPDFReportScope(ctx, v.TenantID, v.ProductID, v.ReleaseID); err != nil {
		return err
	}
	return r.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: v.ID, TenantID: v.TenantID, ReportType: v.ReportType, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Title: v.Title, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
