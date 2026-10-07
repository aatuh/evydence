package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Historical setup is test-only: real root guards precede receipt lookup, and
// real writes use the isolated command clone. Neither physical object staging
// nor an external signer observation is undone by a failed database command.
// These fixtures are not native SQL locking, durability or provider evidence.
type reportSigningFixtureCommands struct{ catalogFixtureCommands }

func pdfFixtureInput(in packageapp.CreatePDFReportInput) app.CreatePDFReportPackageInput {
	return app.CreatePDFReportPackageInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title}
}
func anomalyFixtureInput(in experimentalapp.AnomalyReportInput) app.AnomalyReportInput {
	return app.AnomalyReportInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID}
}
func signingOperationFixtureInput(in verificationapp.SigningOperationInput) app.CreateSigningOperationInput {
	return app.CreateSigningOperationInput{ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash}
}
func pdfFixtureModel(v domain.PDFReportPackage) packagedomain.PDFReportPackage {
	return packagedomain.PDFReportPackage{ID: v.ID, TenantID: v.TenantID, ReportType: v.ReportType, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Title: v.Title, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func anomalyFixtureModel(v domain.AnomalyReport) experimentaldomain.AnomalyReport {
	signals := make([]experimentaldomain.AnomalySignal, len(v.Signals))
	for i, s := range v.Signals {
		signals[i] = experimentaldomain.AnomalySignal{Name: s.Name, Severity: s.Severity, Detail: s.Detail}
	}
	return experimentaldomain.AnomalyReport{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Result: v.Result, Signals: signals, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func signingOperationFixtureModel(v domain.SigningOperation) verificationdomain.SigningOperation {
	checks := make([]verificationdomain.VerifyCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = verificationdomain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail}
	}
	return verificationdomain.SigningOperation{ID: v.ID, TenantID: v.TenantID, ProviderID: v.ProviderID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, ProviderRequestID: v.ProviderRequestID, SignatureRef: v.SignatureRef, Result: v.Result, Checks: checks, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (f reportSigningFixtureCommands) AuthorizeCreatePDFReportPackage(ctx context.Context, a domain.Actor, in packageapp.CreatePDFReportInput) error {
	return f.commandLedger(ctx).AuthorizeCreatePDFReportPackage(ctx, a, pdfFixtureInput(in))
}
func (f reportSigningFixtureCommands) CreatePDFReportPackage(ctx context.Context, a domain.Actor, in packageapp.CreatePDFReportInput) (packagedomain.PDFReportPackage, error) {
	v, err := f.commandLedger(ctx).CreatePDFReportPackage(ctx, a, pdfFixtureInput(in))
	return pdfFixtureModel(v), err
}
func (f reportSigningFixtureCommands) AuthorizeGenerateAnomalyReport(ctx context.Context, a domain.Actor, in experimentalapp.AnomalyReportInput) error {
	return f.commandLedger(ctx).AuthorizeGenerateAnomalyReport(ctx, a, anomalyFixtureInput(in))
}
func (f reportSigningFixtureCommands) GenerateAnomalyReport(ctx context.Context, a domain.Actor, in experimentalapp.AnomalyReportInput) (experimentaldomain.AnomalyReport, error) {
	v, err := f.commandLedger(ctx).GenerateAnomalyReport(ctx, a, anomalyFixtureInput(in))
	return anomalyFixtureModel(v), err
}
func (f reportSigningFixtureCommands) AuthorizeCreateSigningOperation(ctx context.Context, a domain.Actor, in verificationapp.SigningOperationInput) error {
	return f.commandLedger(ctx).AuthorizeCreateSigningOperation(ctx, a, signingOperationFixtureInput(in))
}
func (f reportSigningFixtureCommands) CreateSigningOperation(ctx context.Context, a domain.Actor, in verificationapp.SigningOperationInput) (verificationdomain.SigningOperation, error) {
	v, err := f.commandLedger(ctx).CreateSigningOperation(ctx, a, signingOperationFixtureInput(in))
	return signingOperationFixtureModel(v), err
}
func (s *Server) bindReportSigningFixturePorts(ledger *app.Ledger) {
	f := reportSigningFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.pdfReportCommands.(reportSigningFixtureCommands); s.pdfReportCommands == nil || fixture {
		s.pdfReportCommands = f
	}
	if _, fixture := s.anomalyReportCommands.(reportSigningFixtureCommands); s.anomalyReportCommands == nil || fixture {
		s.anomalyReportCommands = f
	}
	if _, fixture := s.signingOperationCommands.(reportSigningFixtureCommands); s.signingOperationCommands == nil || fixture {
		s.signingOperationCommands = f
	}
}

var (
	_ PDFReportCommands        = reportSigningFixtureCommands{}
	_ AnomalyReportCommands    = reportSigningFixtureCommands{}
	_ SigningOperationCommands = reportSigningFixtureCommands{}
)
