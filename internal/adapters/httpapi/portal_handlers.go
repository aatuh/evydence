package httpapi

import (
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) createCustomerPortalAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PackageID    string    `json:"package_id"`
		CustomerName string    `json:"customer_name"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		access, secret, err := s.ledger.CreateCustomerPortalAccess(ctx, actor, app.CreateCustomerPortalAccessInput{PackageID: req.PackageID, CustomerName: req.CustomerName, ExpiresAt: req.ExpiresAt})
		return http.StatusCreated, map[string]any{"access": access, "secret": secret}, err
	})
}

func (s *Server) accessCustomerPortalPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
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
	pkg, err := s.ledger.AccessCustomerPortalPackage(r.Context(), req.Token)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, pkg)
}

func (s *Server) downloadCustomerPortalPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
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
	archive, err := s.ledger.ExportCustomerPortalPackageArchive(r.Context(), req.Token)
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
