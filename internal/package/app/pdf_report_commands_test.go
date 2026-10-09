package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type pdfCommandFixture struct {
	scope   PDFReportScope
	phase   string
	body    []byte
	stages  int
	reports []packagedomain.PDFReportPackage
	audits  []application.AuditEvent
	cancel  context.CancelFunc
}

func (f *pdfCommandFixture) Authorize(ctx context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.phase == "authorization" || !r.ScopeOnly && f.phase == "root authorization" {
		return application.ErrForbidden
	}
	return nil
}
func (f *pdfCommandFixture) ExecutePDFReport(ctx context.Context, _ string, fn func(context.Context, PDFReportTransaction) error) error {
	r, a := len(f.reports), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errGraphUnit
	}
	if err != nil {
		f.reports, f.audits = f.reports[:r], f.audits[:a]
	}
	return err
}
func (f *pdfCommandFixture) ReadPDFReportScope(context.Context, string, string, string) (PDFReportScope, error) {
	if f.phase == "scope" {
		return PDFReportScope{}, errGraphUnit
	}
	return f.scope, nil
}
func (f *pdfCommandFixture) StagePDFReportPayload(_ context.Context, tenant, digest string, raw []byte, at time.Time) (string, error) {
	f.stages++
	f.body = append([]byte(nil), raw...)
	if f.phase == "stage" {
		return "", errGraphUnit
	}
	return "object://tenants/" + tenant + "/pdf", nil
}
func (f *pdfCommandFixture) InsertPDFReportPackage(_ context.Context, v packagedomain.PDFReportPackage) error {
	if f.phase == "insert" {
		return errGraphUnit
	}
	f.reports = append(f.reports, v)
	return nil
}
func (f *pdfCommandFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errGraphUnit
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func (f *pdfCommandFixture) HashPackageBytes(ctx context.Context, b []byte) (string, error) {
	if f.phase == "hash" {
		return "", errGraphUnit
	}
	if f.phase == "invalid hash" {
		return "sha256:bad", nil
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(b)), ctx.Err()
}
func newPDFCommandFixture(t *testing.T) (*PDFReportCommands, *pdfCommandFixture, identitydomain.Actor, CreatePDFReportInput) {
	t.Helper()
	f := &pdfCommandFixture{scope: PDFReportScope{TenantID: "tenant", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}}
	n := 0
	c, err := NewPDFReportCommands(PDFReportCommandConfig{Transactions: f, Authorizer: f, Hasher: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 6, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{ScopeReportRead}}, CreatePDFReportInput{ReportType: "release_readiness", ProductID: "product", ReleaseID: "release", Title: "Readiness"}
}
func TestPDFCommandPreservesBytesAndPublishesOnlyCommittedMetadata(t *testing.T) {
	c, f, a, in := newPDFCommandFixture(t)
	v, err := c.CreatePDFReportPackage(t.Context(), a, in)
	const want = "%PDF-1.4\n% Evydence reproducible report\n1 0 obj << /Type /Catalog >> endobj\n% Readiness\n% compliance readiness evidence only\n%%EOF\n"
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(want)))
	if err != nil || string(f.body) != want || v.PayloadHash != hash || v.PayloadSize != int64(len(want)) || v.PayloadRef != "object://tenants/tenant/pdf" || v.SchemaVersion != packagedomain.PDFReportPackageVersion || v.CreatedAt.Nanosecond() != 123456000 || len(f.reports) != 1 || len(f.audits) != 1 || f.audits[0].PayloadHash != hash || f.audits[0].SubjectID != v.ID || f.audits[0].EntryType != "pdf_report.created" {
		t.Fatal("PDF packaging contract changed", v, err)
	}
	v.Limitations[0] = "changed"
	if f.reports[0].Limitations[0] == "changed" {
		t.Fatal("returned PDF mutated immutable record")
	}
	before := f.stages
	if err := c.AuthorizeCreatePDFReportPackage(t.Context(), a, in); err != nil || f.stages != before || len(f.reports) != 1 || len(f.audits) != 1 {
		t.Fatal("replay guard staged or regenerated a PDF", err)
	}
}
func TestPDFCommandFailuresReturnNoUncommittedReport(t *testing.T) {
	for _, phase := range []string{"authorization", "root authorization", "scope", "foreign scope", "mismatched root", "hash", "invalid hash", "stage", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newPDFCommandFixture(t)
			f.phase = phase
			want := errGraphUnit
			ctx := t.Context()
			switch phase {
			case "authorization", "root authorization":
				want = application.ErrForbidden
			case "foreign scope":
				f.scope.TenantID = "other"
				want = ErrNotFound
			case "mismatched root":
				f.scope.Resources.ProductID = "other"
				want = ErrNotFound
			case "invalid hash":
				want = ErrValidation
			case "cancel":
				ctx, f.cancel = context.WithCancel(ctx)
				defer f.cancel()
				want = context.Canceled
			}
			v, err := c.CreatePDFReportPackage(ctx, a, in)
			if !errors.Is(err, want) || !reflect.DeepEqual(v, packagedomain.PDFReportPackage{}) || len(f.reports)+len(f.audits) != 0 {
				t.Fatal("uncommitted PDF escaped", v, err)
			}
			if strings.Contains(phase, "authorization") || phase == "scope" || phase == "foreign scope" || phase == "mismatched root" {
				if f.stages != 0 {
					t.Fatal("denied PDF staged sensitive bytes")
				}
			}
		})
	}
}
func TestPDFInputValidatesRawBoundsAndSingleLineTitle(t *testing.T) {
	_, _, _, valid := newPDFCommandFixture(t)
	for _, edit := range []func(*CreatePDFReportInput){
		func(v *CreatePDFReportInput) { v.Title = "Title\n2 0 obj" },
		func(v *CreatePDFReportInput) { v.Title = "\nTitle" },
		func(v *CreatePDFReportInput) { v.Title = "Title\x00" },
		func(v *CreatePDFReportInput) { v.Title = "Title\u009f" },
		func(v *CreatePDFReportInput) { v.Title = string([]byte{255}) },
		func(v *CreatePDFReportInput) { v.Title = strings.Repeat(" ", MaxPDFTitleBytes+1) },
		func(v *CreatePDFReportInput) { v.ReportType = strings.Repeat("x", MaxPDFReportTypeBytes+1) },
		func(v *CreatePDFReportInput) { v.ProductID = strings.Repeat(" ", 1025) + "product" },
		func(v *CreatePDFReportInput) { v.ProductID, v.ReleaseID = "", "" },
	} {
		in := valid
		edit(&in)
		if _, err := NormalizePDFReportInput(in); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid PDF input accepted", err)
		}
	}
	valid.Title = " Readiness "
	valid.ReportType = " release_readiness "
	valid.ProductID = ""
	v, err := NormalizePDFReportInput(valid)
	if err != nil || v.Title != "Readiness" || v.ReportType != "release_readiness" || v.ProductID != "" {
		t.Fatal("valid release-only PDF input changed", v, err)
	}
}
