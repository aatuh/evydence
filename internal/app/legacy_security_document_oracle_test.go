package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// Unchanged historical security-document facades; never production wiring.
type UploadSecurityScanInput struct {
	ProductID  string
	ReleaseID  string
	ArtifactID string
	Category   string
	Format     string
	Scanner    string
	TargetRef  string
	Raw        []byte
}

type UploadManualSecurityDocumentInput struct {
	ProductID    string
	ReleaseID    string
	DocumentType string
	Title        string
	Sensitivity  string
	Raw          []byte
	MediaType    string
}

func (l *Ledger) UploadSecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	value, err := l.evidenceCommands.UploadSecurityScan(ctx, actor, evidenceapp.UploadSecurityScanInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Category: in.Category,
		Format: in.Format, Scanner: in.Scanner, TargetRef: in.TargetRef, Raw: append([]byte(nil), in.Raw...),
	})
	return securityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadManualSecurityDocument(ctx context.Context, actor domain.Actor, in UploadManualSecurityDocumentInput) (domain.ManualSecurityDocument, error) {
	value, err := l.evidenceCommands.UploadManualSecurityDocument(ctx, actor, evidenceapp.UploadManualSecurityDocumentInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, DocumentType: in.DocumentType, Title: in.Title,
		Sensitivity: in.Sensitivity, Raw: append([]byte(nil), in.Raw...), MediaType: in.MediaType,
	})
	return manualSecurityDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}
