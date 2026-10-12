package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SecurityDocumentCommands interface {
	AuthorizeUploadSecurityScan(context.Context, identitydomain.Actor, evidenceapp.UploadSecurityScanInput) error
	AuthorizeUploadManualSecurityDocument(context.Context, identitydomain.Actor, evidenceapp.UploadManualSecurityDocumentInput) error
	UploadSecurityScan(context.Context, identitydomain.Actor, evidenceapp.UploadSecurityScanInput) (evidencedomain.SecurityScan, error)
	UploadManualSecurityDocument(context.Context, identitydomain.Actor, evidenceapp.UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error)
}
type securityScanPayload struct {
	ProductID  string          `json:"product_id"`
	ReleaseID  string          `json:"release_id"`
	ArtifactID string          `json:"artifact_id"`
	Format     string          `json:"format"`
	Scanner    string          `json:"scanner"`
	TargetRef  string          `json:"target_ref"`
	Payload    json.RawMessage `json:"payload"`
}

func (s *Server) uploadDurableSecurityScan(w http.ResponseWriter, r *http.Request, api bool) {
	var in evidenceapp.UploadSecurityScanInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req securityScanPayload
		category := "api_security"
		if api {
			if err := decodeJSON(body, &req); err != nil {
				return err
			}
		} else {
			var scan struct {
				securityScanPayload
				Category string `json:"category"`
			}
			if err := decodeJSON(body, &scan); err != nil {
				return err
			}
			req, category = scan.securityScanPayload, scan.Category
		}
		if err := validateNonNullableObjectFields(body, "product_id", "release_id", "artifact_id", "format", "scanner", "target_ref", "category", "payload"); err != nil {
			return err
		}
		in = evidenceapp.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Category: category, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload}
		return mapEvidenceCreationCommandError(s.securityDocumentCommands.AuthorizeUploadSecurityScan(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.securityDocumentCommands.UploadSecurityScan(ctx, a, in)
		return http.StatusCreated, domain.SecurityScanFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
func (s *Server) uploadDurableManualSecurityDocument(w http.ResponseWriter, r *http.Request) {
	var in evidenceapp.UploadManualSecurityDocumentInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			ProductID    string          `json:"product_id"`
			ReleaseID    string          `json:"release_id"`
			DocumentType string          `json:"document_type"`
			Title        string          `json:"title"`
			Sensitivity  string          `json:"sensitivity"`
			MediaType    string          `json:"media_type"`
			Payload      json.RawMessage `json:"payload"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "product_id", "release_id", "document_type", "title", "sensitivity", "media_type", "payload"); err != nil {
			return err
		}
		in = evidenceapp.UploadManualSecurityDocumentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, DocumentType: req.DocumentType, Title: req.Title, Sensitivity: req.Sensitivity, MediaType: req.MediaType, Raw: req.Payload}
		return mapEvidenceCreationCommandError(s.securityDocumentCommands.AuthorizeUploadManualSecurityDocument(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.securityDocumentCommands.UploadManualSecurityDocument(ctx, a, in)
		return http.StatusCreated, domain.ManualSecurityDocumentFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
