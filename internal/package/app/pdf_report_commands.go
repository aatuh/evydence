package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxPDFTitleBytes      = 64 << 10
	MaxPDFReportTypeBytes = 128
)

type CreatePDFReportInput struct{ ReportType, ProductID, ReleaseID, Title string }
type PDFReportScope struct {
	TenantID  string
	Resources application.ResourceReferences
}
type PDFReportReader interface {
	ReadPDFReportScope(context.Context, string, string, string) (PDFReportScope, error)
}
type PDFReportTransaction interface {
	PDFReportReader
	// The adapter verifies staged bytes and records lifecycle metadata plus its
	// finalizer job in this transaction. An empty reference is metadata-only.
	StagePDFReportPayload(context.Context, string, string, []byte, time.Time) (string, error)
	InsertPDFReportPackage(context.Context, packagedomain.PDFReportPackage) error
	application.Authorizer
	application.AuditAppender
}
type PDFReportTransactions interface {
	ExecutePDFReport(context.Context, string, func(context.Context, PDFReportTransaction) error) error
}
type PDFReportCommandConfig struct {
	Transactions PDFReportTransactions
	Authorizer   application.Authorizer
	Hasher       ReportBytesHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PDFReportCommands struct{ config PDFReportCommandConfig }

func NewPDFReportCommands(c PDFReportCommandConfig) (*PDFReportCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PDFReportCommands{c}, nil
}
func singleLinePDFText(v string, limit int) bool {
	if !graphText(v, limit) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}
func NormalizePDFReportInput(in CreatePDFReportInput) (CreatePDFReportInput, error) {
	if !singleLinePDFText(in.Title, MaxPDFTitleBytes) || !singleLinePDFText(in.ReportType, MaxPDFReportTypeBytes) {
		return in, ErrValidation
	}
	var err error
	in.ProductID, in.ReleaseID, err = NormalizeProductReleaseIDs(in.ProductID, in.ReleaseID)
	if err != nil {
		return in, err
	}
	in.ReportType, in.Title = strings.TrimSpace(in.ReportType), strings.TrimSpace(in.Title)
	if in.ReportType == "" || in.Title == "" {
		return in, ErrValidation
	}
	return in, nil
}

// Retains the versioned minimal title-only envelope. It is not a renderer of
// evidence, findings, report-type-specific pages, or a compliance conclusion.
func PDFReportPayload(in CreatePDFReportInput) ([]byte, error) {
	in, err := NormalizePDFReportInput(in)
	if err != nil {
		return nil, err
	}
	body := []byte("%PDF-1.4\n% Evydence reproducible report\n1 0 obj << /Type /Catalog >> endobj\n% " + in.Title + "\n% compliance readiness evidence only\n%%EOF\n")
	if len(body) > MaxGeneratedReportBytes {
		return nil, ErrValidation
	}
	return body, nil
}
func (c *PDFReportCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreatePDFReportInput) (CreatePDFReportInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	v, err := NormalizePDFReportInput(in)
	if err != nil {
		return v, err
	}
	if !graphID(a.TenantID) || !graphID(auditActorID(a)) {
		return v, application.ErrUnauthorized
	}
	return v, c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true})
}
func readAuthorizedPDFScope(ctx context.Context, tx PDFReportTransaction, a identitydomain.Actor, in CreatePDFReportInput) error {
	if tx == nil {
		return ErrValidation
	}
	s, err := tx.ReadPDFReportScope(ctx, a.TenantID, in.ProductID, in.ReleaseID)
	if err != nil {
		return err
	}
	if err := ValidateProductReleaseScope(a.TenantID, in.ProductID, in.ReleaseID, s.TenantID, s.Resources); err != nil {
		return err
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, Resources: s.Resources})
}
func (c *PDFReportCommands) AuthorizeCreatePDFReportPackage(ctx context.Context, a identitydomain.Actor, in CreatePDFReportInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecutePDFReport(ctx, a.TenantID, func(ctx context.Context, tx PDFReportTransaction) error {
		if err := readAuthorizedPDFScope(ctx, tx, a, in); err != nil {
			return err
		}
		return contextError(ctx)
	})
}
func (c *PDFReportCommands) CreatePDFReportPackage(ctx context.Context, a identitydomain.Actor, in CreatePDFReportInput) (packagedomain.PDFReportPackage, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.PDFReportPackage{}, err
	}
	var out packagedomain.PDFReportPackage
	err = c.config.Transactions.ExecutePDFReport(ctx, a.TenantID, func(ctx context.Context, tx PDFReportTransaction) error {
		if err := readAuthorizedPDFScope(ctx, tx, a, in); err != nil {
			return err
		}
		body, err := PDFReportPayload(in)
		if err != nil {
			return err
		}
		digest, err := c.config.Hasher.HashPackageBytes(ctx, body)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(digest, "sha256:") {
			return ErrValidation
		}
		if raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil || len(raw) != 32 {
			return ErrValidation
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		id := c.config.IDs.NewID("pdf")
		if !graphID(id) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
			return ErrValidation
		}
		ref, err := tx.StagePDFReportPayload(ctx, a.TenantID, digest, body, at)
		if err != nil {
			return err
		}
		if !graphText(ref, 4096) || strings.TrimSpace(ref) != ref {
			return ErrValidation
		}
		out = packagedomain.PDFReportPackage{ID: id, TenantID: a.TenantID, ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title, PayloadRef: ref, PayloadHash: digest, PayloadSize: int64(len(body)), Limitations: []string{"PDF output is reproducible report packaging and does not provide legal compliance or security certification."}, SchemaVersion: packagedomain.PDFReportPackageVersion, CreatedAt: at}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertPDFReportPackage(ctx, ClonePDFReport(out)); err != nil {
			return err
		}
		e := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "pdf_report.created", SubjectType: "pdf_report", SubjectID: out.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), PayloadHash: digest, OccurredAt: at}
		if !graphID(e.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, e); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.PDFReportPackage{}, err
	}
	return ClonePDFReport(out), nil
}
func ClonePDFReport(v packagedomain.PDFReportPackage) packagedomain.PDFReportPackage {
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func EncodePDFReport(v packagedomain.PDFReportPackage) ([]byte, error) {
	m := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "report_type": v.ReportType, "title": v.Title, "payload_hash": v.PayloadHash, "payload_size": v.PayloadSize, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	if v.ProductID != "" {
		m["product_id"] = v.ProductID
	}
	if v.ReleaseID != "" {
		m["release_id"] = v.ReleaseID
	}
	if v.PayloadRef != "" {
		m["payload_ref"] = v.PayloadRef
	}
	return json.Marshal(m)
}
