package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memoryPDFSigningPorts interface {
	packageapp.PDFReportReader
	verificationapp.SigningOperationReader
	InsertFocusedPDFReportPackage(context.Context, packagedomain.PDFReportPackage) error
	InsertFocusedSigningOperation(context.Context, verificationdomain.Signature, verificationdomain.SigningOperation) error
}

func memoryPDFSigningFixture(t *testing.T) (*memoryUnitOfWork, memoryPDFSigningPorts) {
	t.Helper()
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Future.(memoryPDFSigningPorts)
	if !ok {
		t.Fatal("memory future repository lacks focused PDF/signing ports")
	}
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.SigningProviders[tenant+"-provider"] = domain.SigningProvider{ID: tenant + "-provider", TenantID: tenant, Name: strings.Repeat("private metadata", 100000), Type: "aws_kms", Status: "active", KeyRef: "key-ref"}
	}
	return tx, r
}

func TestMemoryPDFSigningScopesReadOnlyBoundedOwnedMetadata(t *testing.T) {
	tx, r := memoryPDFSigningFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []struct{ product, release string }{{"tenant-product", ""}, {"", "tenant-release"}, {"tenant-product", "tenant-release"}} {
		s, err := r.ReadPDFReportScope(t.Context(), "tenant", raw.product, raw.release)
		if err != nil || s.TenantID != "tenant" || s.Resources != (application.ResourceReferences{ProductID: "tenant-product", ReleaseID: raw.release}) {
			t.Fatal("PDF scope lost current coordinates", s, err)
		}
	}
	for _, root := range []struct{ kind, id string }{{"tenant", "tenant"}, {"product", "tenant-product"}, {"release", "tenant-release"}, {"evidence", "tenant-evidence"}, {"customer_package", "tenant-package"}} {
		s, err := r.ReadSigningOperationScope(t.Context(), "tenant", root.kind, root.id)
		if err != nil || s != (verificationapp.SigningOperationScope{TenantID: "tenant", SubjectType: root.kind, SubjectID: root.id}) {
			t.Fatal("signing scope widened projection", s, err)
		}
		if _, err := r.ReadSigningOperationScope(t.Context(), "tenant", root.kind, strings.Replace(root.id, "tenant", "foreign", 1)); !errors.Is(err, ErrNotFound) {
			t.Fatal("signing root crossed tenant", root, err)
		}
	}
	p, err := r.ReadSigningOperationProvider(t.Context(), "tenant", "tenant-provider")
	if err != nil || p != (verificationapp.SigningOperationProvider{ID: "tenant-provider", TenantID: "tenant", Type: "aws_kms", Status: "active", KeyRef: "key-ref"}) {
		t.Fatal("provider read transferred private metadata", p, err)
	}
	if _, err := r.ReadSigningOperationProvider(t.Context(), "tenant", "foreign-provider"); !errors.Is(err, ErrNotFound) {
		t.Fatal("provider read crossed tenant", err)
	}
	if _, err := r.ReadPDFReportScope(t.Context(), "tenant", "foreign-product", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("PDF read crossed tenant", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("scope reads changed storage")
	}
	pv := tx.state.SigningProviders[p.ID]
	pv.KeyRef = strings.Repeat("x", 4097)
	tx.state.SigningProviders[p.ID] = pv
	if got, err := r.ReadSigningOperationProvider(t.Context(), "tenant", p.ID); !errors.Is(err, ErrValidation) || got != (verificationapp.SigningOperationProvider{}) {
		t.Fatal("oversized provider metadata escaped", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadPDFReportScope(ctx, "tenant", "tenant-product", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("scope ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadSigningOperationScope(t.Context(), "tenant", "release", "tenant-release"); !errors.Is(err, ErrConflict) {
		t.Fatal("scope accepted closed transaction", err)
	}
}

func TestMemoryFocusedPDFSigningWritesPreserveCompleteDetachedRecords(t *testing.T) {
	tx, r := memoryPDFSigningFixture(t)
	in := packageapp.CreatePDFReportInput{ReportType: "release_readiness", ProductID: "tenant-product", ReleaseID: "tenant-release", Title: "Readiness"}
	raw, err := packageapp.PDFReportPayload(in)
	if err != nil {
		t.Fatal(err)
	}
	pdf := packagedomain.PDFReportPackage{ID: "pdf", TenantID: "tenant", ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title, PayloadHash: BytesPayloadSource(raw).Digest, PayloadSize: int64(len(raw)), Limitations: []string{"Review"}, SchemaVersion: packagedomain.PDFReportPackageVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedPDFReportPackage(t.Context(), pdf); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.state.PDFReports[pdf.ID], domain.PDFReportPackage{ID: pdf.ID, TenantID: pdf.TenantID, ReportType: pdf.ReportType, ProductID: pdf.ProductID, ReleaseID: pdf.ReleaseID, Title: pdf.Title, PayloadHash: pdf.PayloadHash, PayloadSize: pdf.PayloadSize, Limitations: pdf.Limitations, SchemaVersion: pdf.SchemaVersion, CreatedAt: pdf.CreatedAt}) {
		t.Fatal("PDF mapper lost fields")
	}
	pdf.Limitations[0] = "mutated"
	if tx.state.PDFReports[pdf.ID].Limitations[0] != "Review" {
		t.Fatal("PDF retained caller metadata")
	}
	sig := verificationdomain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "release", SubjectID: "tenant-release", KeyID: "tenant-provider", Algorithm: "external-aws_kms", Value: "private signature", CreatedAt: fixedNow()}
	op := verificationdomain.SigningOperation{ID: "operation", TenantID: "tenant", ProviderID: "tenant-provider", SubjectType: "release", SubjectID: "tenant-release", PayloadHash: "sha256:" + strings.Repeat("a", 64), CanonicalPayloadHash: "sha256:" + strings.Repeat("b", 64), RequestID: "request", ProviderRequestID: "provider-request", SignatureRef: sig.ID, Result: "passed", Checks: []verificationdomain.VerifyCheck{{Name: "binding", Result: "passed", Detail: "Recorded"}}, SchemaVersion: verificationdomain.SigningOperationVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedSigningOperation(t.Context(), sig, op); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.state.SigningOperations[op.ID], domain.SigningOperation{ID: op.ID, TenantID: op.TenantID, ProviderID: op.ProviderID, SubjectType: op.SubjectType, SubjectID: op.SubjectID, PayloadHash: op.PayloadHash, CanonicalPayloadHash: op.CanonicalPayloadHash, RequestID: op.RequestID, ProviderRequestID: op.ProviderRequestID, SignatureRef: op.SignatureRef, Result: op.Result, Checks: []domain.VerifyCheck{{Name: "binding", Result: "passed", Detail: "Recorded"}}, SchemaVersion: op.SchemaVersion, CreatedAt: op.CreatedAt}) {
		t.Fatal("operation mapper lost fields")
	}
	if !reflect.DeepEqual(tx.state.Signatures[sig.ID], domain.Signature{ID: sig.ID, TenantID: sig.TenantID, SubjectType: sig.SubjectType, SubjectID: sig.SubjectID, KeyID: sig.KeyID, Algorithm: sig.Algorithm, Value: sig.Value, CreatedAt: sig.CreatedAt}) {
		t.Fatal("signature mapper lost fields")
	}
	op.Checks[0].Detail = "mutated"
	if tx.state.SigningOperations[op.ID].Checks[0].Detail != "Recorded" {
		t.Fatal("operation retained caller checks")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	pdf.ID, pdf.ReleaseID = "wrong-root", "foreign-release"
	if err := r.InsertFocusedPDFReportPackage(t.Context(), pdf); !errors.Is(err, ErrNotFound) {
		t.Fatal("PDF persisted foreign root", err)
	}
	op.ID, op.ProviderID, sig.ID, sig.KeyID, op.SignatureRef = "wrong-provider", "foreign-provider", "new-signature", "foreign-provider", "new-signature"
	if err := r.InsertFocusedSigningOperation(t.Context(), sig, op); !errors.Is(err, ErrNotFound) {
		t.Fatal("operation persisted foreign provider", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("failed insert changed records")
	}
}
