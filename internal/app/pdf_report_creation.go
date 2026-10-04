package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func (l *Ledger) AuthorizeCreatePDFReportPackage(ctx context.Context, a domain.Actor, in CreatePDFReportPackageInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeReportRead); err != nil {
		return err
	}
	v, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title})
	if err != nil {
		return fromPackageContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeProductReleaseLocked(a, ScopeReportRead, v.ProductID, v.ReleaseID)
	return err
}
