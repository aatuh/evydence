package httpapi

import (
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) createCustomerPortalAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PackageID     string    `json:"package_id"`
		CustomerName  string    `json:"customer_name"`
		ReviewerName  string    `json:"reviewer_name"`
		ReviewerEmail string    `json:"reviewer_email"`
		RequireNDA    bool      `json:"require_nda"`
		Watermark     string    `json:"watermark"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		access, secret, err := s.ledger.CreateCustomerPortalAccess(ctx, actor, app.CreateCustomerPortalAccessInput{PackageID: req.PackageID, CustomerName: req.CustomerName, ReviewerName: req.ReviewerName, ReviewerEmail: req.ReviewerEmail, RequireNDA: req.RequireNDA, Watermark: req.Watermark, ExpiresAt: req.ExpiresAt})
		return http.StatusCreated, map[string]any{"access": access, "secret": secret}, err
	})
}

func (s *Server) listCustomerPortalAccess(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	access, err := s.ledger.ListCustomerPortalAccess(r.Context(), actor, r.URL.Query().Get("package_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, access)
}

func (s *Server) revokeCustomerPortalAccess(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		access, err := s.ledger.RevokeCustomerPortalAccess(ctx, actor, r.PathValue("id"))
		return http.StatusOK, access, err
	})
}

func (s *Server) accessCustomerPortalPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token         string `json:"token"`
		NDAAccepted   bool   `json:"nda_accepted"`
		NDAAcceptedBy string `json:"nda_accepted_by"`
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	pkg, err := s.ledger.AccessCustomerPortalPackageWithAcceptance(r.Context(), req.Token, app.CustomerPortalAcceptanceInput{NDAAccepted: req.NDAAccepted, NDAAcceptedBy: req.NDAAcceptedBy})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, pkg)
}

func (s *Server) downloadCustomerPortalPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token         string `json:"token"`
		NDAAccepted   bool   `json:"nda_accepted"`
		NDAAcceptedBy string `json:"nda_accepted_by"`
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	archive, err := s.ledger.ExportCustomerPortalPackageArchiveWithAcceptance(r.Context(), req.Token, app.CustomerPortalAcceptanceInput{NDAAccepted: req.NDAAccepted, NDAAcceptedBy: req.NDAAcceptedBy})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeArchive(w, archive)
}

func (s *Server) createQuestionnaireTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string                         `json:"name"`
		Version   string                         `json:"version"`
		Questions []domain.QuestionnaireQuestion `json:"questions"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		tpl, err := s.ledger.CreateQuestionnaireTemplate(ctx, actor, app.CreateQuestionnaireTemplateInput{Name: req.Name, Version: req.Version, Questions: req.Questions})
		return http.StatusCreated, tpl, err
	})
}

func (s *Server) createQuestionnairePackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string `json:"template_id"`
		PackageID  string `json:"package_id"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pkg, err := s.ledger.CreateQuestionnairePackage(ctx, actor, app.CreateQuestionnairePackageInput{TemplateID: req.TemplateID, PackageID: req.PackageID, ProductID: req.ProductID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, pkg, err
	})
}

func (s *Server) createQuestionnaireAnswerLibraryEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		QuestionID   string   `json:"question_id"`
		EvidenceType string   `json:"evidence_type"`
		ControlID    string   `json:"control_id"`
		ProductID    string   `json:"product_id"`
		ReleaseID    string   `json:"release_id"`
		Answer       string   `json:"answer"`
		EvidenceIDs  []string `json:"evidence_ids"`
		Limitations  []string `json:"limitations"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		entry, err := s.ledger.CreateQuestionnaireAnswerLibraryEntry(ctx, actor, app.CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: req.QuestionID, EvidenceType: req.EvidenceType, ControlID: req.ControlID, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Answer: req.Answer, EvidenceIDs: req.EvidenceIDs, Limitations: req.Limitations})
		return http.StatusCreated, entry, err
	})
}

func (s *Server) listQuestionnaireAnswerLibrary(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	entries, err := s.ledger.ListQuestionnaireAnswerLibrary(r.Context(), actor, app.ListQuestionnaireAnswerLibraryInput{QuestionID: r.URL.Query().Get("question_id"), ProductID: r.URL.Query().Get("product_id"), ReleaseID: r.URL.Query().Get("release_id")})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, entries)
}
