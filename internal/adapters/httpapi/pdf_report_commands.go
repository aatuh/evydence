package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type PDFReportCommands interface {
	AuthorizeCreatePDFReportPackage(context.Context, identitydomain.Actor, packageapp.CreatePDFReportInput) error
	CreatePDFReportPackage(context.Context, identitydomain.Actor, packageapp.CreatePDFReportInput) (packagedomain.PDFReportPackage, error)
}

func decodePDFReportRequest(body []byte) (packageapp.CreatePDFReportInput, error) {
	var req struct {
		ReportType string `json:"report_type"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
		Title      string `json:"title"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreatePDFReportInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "report_type", "product_id", "release_id", "title"); err != nil {
		return packageapp.CreatePDFReportInput{}, err
	}
	v, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: req.ReportType, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title})
	return v, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurablePDFReportPackage(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreatePDFReportInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePDFReportRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.pdfReportCommands.AuthorizeCreatePDFReportPackage(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.pdfReportCommands.CreatePDFReportPackage(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		raw, err := packageapp.EncodePDFReport(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
