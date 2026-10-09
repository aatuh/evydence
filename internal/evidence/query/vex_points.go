package query

import (
	"context"
	"strings"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// VEXDocumentPoint binds a parsed document to current tenant-owned parents.
type VEXDocumentPoint struct {
	Document  evidencedomain.VEXDocument
	ProductID string
}

// VEXImportReportPoint retains the document coordinates used to authorize a
// report; callers supply a VEX document ID, not a report ID.
type VEXImportReportPoint struct {
	Document VEXDocumentPoint
	Report   evidencedomain.VEXImportReport
}

type VEXPointReader interface {
	GetVEXDocumentPoint(context.Context, string, string) (VEXDocumentPoint, error)
	GetVEXImportReportPoint(context.Context, string, string) (VEXImportReportPoint, error)
}

type VEXPoints struct{ reader VEXPointReader }

func NewVEXPoints(reader VEXPointReader) (*VEXPoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &VEXPoints{reader: reader}, nil
}

func (s *VEXPoints) GetVEXDocument(ctx context.Context, actor identitydomain.Actor, id string) (evidencedomain.VEXDocument, error) {
	if s == nil || ctx == nil {
		return evidencedomain.VEXDocument{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencedomain.VEXDocument{}, ErrNotFound
	}
	point, err := s.reader.GetVEXDocumentPoint(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	if !validVEXDocumentPoint(point, actor.TenantID, id) {
		return evidencedomain.VEXDocument{}, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{ProductID: point.ProductID, ReleaseID: point.Document.ReleaseID}, false); err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	return point.Document, nil
}

func (s *VEXPoints) GetVEXImportReport(ctx context.Context, actor identitydomain.Actor, vexID string) (evidencedomain.VEXImportReport, error) {
	if s == nil || ctx == nil {
		return evidencedomain.VEXImportReport{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.VEXImportReport{}, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return evidencedomain.VEXImportReport{}, err
	}
	vexID = strings.TrimSpace(vexID)
	if vexID == "" {
		return evidencedomain.VEXImportReport{}, ErrNotFound
	}
	point, err := s.reader.GetVEXImportReportPoint(ctx, actor.TenantID, vexID)
	if err != nil {
		return evidencedomain.VEXImportReport{}, err
	}
	if !validVEXDocumentPoint(point.Document, actor.TenantID, vexID) || !validVEXImportReportPoint(point, actor.TenantID) {
		return evidencedomain.VEXImportReport{}, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{ProductID: point.Document.ProductID, ReleaseID: point.Document.Document.ReleaseID}, false); err != nil {
		return evidencedomain.VEXImportReport{}, err
	}
	return point.Report, nil
}

func validVEXDocumentPoint(point VEXDocumentPoint, tenantID, id string) bool {
	document := point.Document
	return document.ID == id && document.TenantID == tenantID && document.EvidenceID != "" &&
		document.Format != "" && document.SchemaVersion != "" && !document.CreatedAt.IsZero() &&
		document.StatementCount >= 0 && (document.ReleaseID == "" || point.ProductID != "")
}

func validVEXImportReportPoint(point VEXImportReportPoint, tenantID string) bool {
	report, document := point.Report, point.Document.Document
	if report.ID == "" || report.TenantID != tenantID || report.VEXDocumentID != document.ID ||
		report.EvidenceID != document.EvidenceID || report.ReleaseID != document.ReleaseID ||
		report.ArtifactID != document.ArtifactID || report.ParserVersion == "" || report.SchemaVersion == "" ||
		report.CreatedAt.IsZero() || report.UpdatedAt.IsZero() || report.UpdatedAt.Before(report.CreatedAt) ||
		report.StatementCount < 0 || report.DecisionsCreated < 0 || report.DecisionsSuperseded < 0 {
		return false
	}
	return report.Status == "accepted" || report.Status == "failed" || report.Status == "parsed"
}
