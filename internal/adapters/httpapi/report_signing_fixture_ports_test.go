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

// PDF, anomaly and signing fixtures use real focused services on memory
// transactions, not historical aggregate generators or readiness snapshots.
// Physical staging and provider observations are not undone by database
// rollback. These fixtures are not SQL locking, durability or provider proof.
type reportSigningFixtureCommands struct {
	catalogFixtureCommands
	objects app.PayloadObjectStore
	signer  app.SigningExecutor
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
	c, err := f.nativePDF(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreatePDFReportPackage(ctx, a, in)
}
func (f reportSigningFixtureCommands) CreatePDFReportPackage(ctx context.Context, a domain.Actor, in packageapp.CreatePDFReportInput) (packagedomain.PDFReportPackage, error) {
	c, err := f.nativePDF(false)
	if err != nil {
		return packagedomain.PDFReportPackage{}, err
	}
	return c.CreatePDFReportPackage(ctx, a, in)
}
func (f reportSigningFixtureCommands) AuthorizeGenerateAnomalyReport(ctx context.Context, a domain.Actor, in experimentalapp.AnomalyReportInput) error {
	c, err := f.nativeAnomaly(true)
	if err != nil {
		return err
	}
	return c.AuthorizeGenerateAnomalyReport(ctx, a, in)
}
func (f reportSigningFixtureCommands) GenerateAnomalyReport(ctx context.Context, a domain.Actor, in experimentalapp.AnomalyReportInput) (experimentaldomain.AnomalyReport, error) {
	c, err := f.nativeAnomaly(false)
	if err != nil {
		return experimentaldomain.AnomalyReport{}, err
	}
	return c.GenerateAnomalyReport(ctx, a, in)
}
func (f reportSigningFixtureCommands) AuthorizeCreateSigningOperation(ctx context.Context, a domain.Actor, in verificationapp.SigningOperationInput) error {
	c, err := f.nativeSigning(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateSigningOperation(ctx, a, in)
}
func (f reportSigningFixtureCommands) CreateSigningOperation(ctx context.Context, a domain.Actor, in verificationapp.SigningOperationInput) (verificationdomain.SigningOperation, error) {
	c, err := f.nativeSigning(false)
	if err != nil {
		return verificationdomain.SigningOperation{}, err
	}
	return c.CreateSigningOperation(ctx, a, in)
}
func (s *Server) bindReportSigningFixturePorts(ledger *app.Ledger) {
	f := reportSigningFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.pdfReportCommands.(reportSigningFixtureCommands); fixture {
		old.ledger = ledger
		s.pdfReportCommands = old
	} else if s.pdfReportCommands == nil {
		s.pdfReportCommands = f
	}
	if _, fixture := s.anomalyReportCommands.(reportSigningFixtureCommands); s.anomalyReportCommands == nil || fixture {
		s.anomalyReportCommands = f
	}
	if old, fixture := s.signingOperationCommands.(reportSigningFixtureCommands); fixture {
		old.ledger = ledger
		s.signingOperationCommands = old
	} else if s.signingOperationCommands == nil {
		s.signingOperationCommands = f
	}
}

var (
	_ PDFReportCommands        = reportSigningFixtureCommands{}
	_ AnomalyReportCommands    = reportSigningFixtureCommands{}
	_ SigningOperationCommands = reportSigningFixtureCommands{}
)
