package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"
	"github.com/aatuh/api-toolkit/v3/idempotent"
	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const maxJSONBody = 2 << 20

type Server struct {
	ledger *app.Ledger
	mux    *http.ServeMux
	specs  *specs.Registry
	routes *routecontracts.Registry
}

func NewServer(ledger *app.Ledger) (*Server, error) {
	if ledger == nil {
		ledger = app.NewLedger(app.Config{})
	}
	mux := http.NewServeMux()
	specRegistry := NewSpecRegistry()
	router := &serveMuxRouter{mux: mux}
	routeRegistry := routecontracts.NewRegistry(router, specRegistry)
	server := &Server{ledger: ledger, mux: mux, specs: specRegistry, routes: routeRegistry}
	if err := server.registerRoutes(); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return secureHeaders(s.mux)
}

func (s *Server) OpenAPI() ([]byte, error) {
	return s.specs.OpenAPI()
}

func (s *Server) ValidateRoutes() error {
	return s.routes.Validate()
}

func (s *Server) registerRoutes() error {
	routes := []struct {
		method  string
		path    string
		op      specs.Operation
		handler http.Handler
	}{
		{http.MethodGet, "/v1/health", op("health", http.MethodGet, "/v1/health", "Health", nil), http.HandlerFunc(s.health)},
		{http.MethodGet, "/v1/version", op("version", http.MethodGet, "/v1/version", "Version", nil), http.HandlerFunc(s.version)},
		{http.MethodGet, "/v1/openapi.json", op("openapi", http.MethodGet, "/v1/openapi.json", "OpenAPI", nil), http.HandlerFunc(s.openapi)},
		{http.MethodPost, "/v1/products", op("createProduct", http.MethodPost, "/v1/products", "Create product", []string{app.ScopeProductWrite}), http.HandlerFunc(s.createProduct)},
		{http.MethodGet, "/v1/products", op("listProducts", http.MethodGet, "/v1/products", "List products", []string{app.ScopeProductRead}), http.HandlerFunc(s.listProducts)},
		{http.MethodPost, "/v1/projects", op("createProject", http.MethodPost, "/v1/projects", "Create project", []string{app.ScopeProjectWrite}), http.HandlerFunc(s.createProject)},
		{http.MethodPost, "/v1/releases", op("createRelease", http.MethodPost, "/v1/releases", "Create release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createRelease)},
		{http.MethodGet, "/v1/releases/{id}", op("getRelease", http.MethodGet, "/v1/releases/{id}", "Get release", []string{app.ScopeReleaseRead}), http.HandlerFunc(s.getRelease)},
		{http.MethodPost, "/v1/releases/{id}/freeze", op("freezeRelease", http.MethodPost, "/v1/releases/{id}/freeze", "Freeze release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.freezeRelease)},
		{http.MethodPost, "/v1/releases/{id}/approve", op("approveRelease", http.MethodPost, "/v1/releases/{id}/approve", "Approve release", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.approveRelease)},
		{http.MethodPost, "/v1/artifacts", op("registerArtifact", http.MethodPost, "/v1/artifacts", "Register artifact", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.registerArtifact)},
		{http.MethodPost, "/v1/evidence", op("createEvidence", http.MethodPost, "/v1/evidence", "Create evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createEvidence)},
		{http.MethodGet, "/v1/evidence", op("listEvidence", http.MethodGet, "/v1/evidence", "List evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.listEvidence)},
		{http.MethodGet, "/v1/evidence/{id}", op("getEvidence", http.MethodGet, "/v1/evidence/{id}", "Get evidence", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/supersede", op("supersedeEvidence", http.MethodPost, "/v1/evidence/{id}/supersede", "Supersede evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.supersedeEvidence)},
		{http.MethodPost, "/v1/evidence/{id}/link", op("linkEvidence", http.MethodPost, "/v1/evidence/{id}/link", "Link evidence", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.linkEvidence)},
		{http.MethodPost, "/v1/sboms", op("uploadSBOM", http.MethodPost, "/v1/sboms", "Upload CycloneDX SBOM", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadSBOM)},
		{http.MethodGet, "/v1/sboms/{id}", op("getSBOM", http.MethodGet, "/v1/sboms/{id}", "Get SBOM", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getSBOM)},
		{http.MethodPost, "/v1/vex", op("uploadVEX", http.MethodPost, "/v1/vex", "Upload OpenVEX document", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadVEX)},
		{http.MethodGet, "/v1/vex/{id}", op("getVEX", http.MethodGet, "/v1/vex/{id}", "Get VEX document", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getVEX)},
		{http.MethodPost, "/v1/vulnerability-scans", op("uploadVulnerabilityScan", http.MethodPost, "/v1/vulnerability-scans", "Upload vulnerability scan", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadVulnerabilityScan)},
		{http.MethodGet, "/v1/vulnerability-scans/{id}", op("getVulnerabilityScan", http.MethodGet, "/v1/vulnerability-scans/{id}", "Get vulnerability scan", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getVulnerabilityScan)},
		{http.MethodPost, "/v1/vulnerability-findings/{id}/decisions", op("createVulnerabilityDecision", http.MethodPost, "/v1/vulnerability-findings/{id}/decisions", "Create vulnerability decision", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.createVulnerabilityDecision)},
		{http.MethodPost, "/v1/openapi-contracts", op("uploadOpenAPIContract", http.MethodPost, "/v1/openapi-contracts", "Upload OpenAPI contract", []string{app.ScopeEvidenceWrite}), http.HandlerFunc(s.uploadOpenAPIContract)},
		{http.MethodGet, "/v1/openapi-contracts/{id}", op("getOpenAPIContract", http.MethodGet, "/v1/openapi-contracts/{id}", "Get OpenAPI contract", []string{app.ScopeEvidenceRead}), http.HandlerFunc(s.getOpenAPIContract)},
		{http.MethodPost, "/v1/policies/evaluate", op("evaluatePolicy", http.MethodPost, "/v1/policies/evaluate", "Evaluate release policy", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.evaluatePolicy)},
		{http.MethodPost, "/v1/exceptions", op("createException", http.MethodPost, "/v1/exceptions", "Create exception", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.createException)},
		{http.MethodGet, "/v1/exceptions", op("listExceptions", http.MethodGet, "/v1/exceptions", "List exceptions", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.listExceptions)},
		{http.MethodPost, "/v1/exceptions/{id}/approve", op("approveException", http.MethodPost, "/v1/exceptions/{id}/approve", "Approve exception", []string{app.ScopeReleaseWrite}), http.HandlerFunc(s.approveException)},
		{http.MethodGet, "/v1/reports/missing-evidence", op("missingEvidenceReport", http.MethodGet, "/v1/reports/missing-evidence", "Missing evidence report", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.missingEvidenceReport)},
		{http.MethodGet, "/v1/reports/release-readiness", op("releaseReadinessReport", http.MethodGet, "/v1/reports/release-readiness", "Release readiness report", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.releaseReadinessReport)},
		{http.MethodPost, "/v1/release-bundles", op("createReleaseBundle", http.MethodPost, "/v1/release-bundles", "Create release bundle", []string{app.ScopeBundleWrite}), http.HandlerFunc(s.createReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}", op("getReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}", "Get release bundle", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundle)},
		{http.MethodGet, "/v1/release-bundles/{id}/manifest", op("getReleaseBundleManifest", http.MethodGet, "/v1/release-bundles/{id}/manifest", "Get release bundle manifest", []string{app.ScopeBundleRead}), http.HandlerFunc(s.getReleaseBundleManifest)},
		{http.MethodGet, "/v1/release-bundles/{id}/verify", op("verifyReleaseBundle", http.MethodGet, "/v1/release-bundles/{id}/verify", "Verify release bundle", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyReleaseBundle)},
		{http.MethodGet, "/v1/audit-chain/verify", op("verifyAuditChain", http.MethodGet, "/v1/audit-chain/verify", "Verify audit chain", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifyAuditChain)},
		{http.MethodGet, "/v1/signing-keys", op("listSigningKeys", http.MethodGet, "/v1/signing-keys", "List signing keys", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.listSigningKeys)},
		{http.MethodPost, "/v1/signing-keys/rotate", op("rotateSigningKey", http.MethodPost, "/v1/signing-keys/rotate", "Rotate signing key", []string{app.ScopeKeysAdmin}), http.HandlerFunc(s.rotateSigningKey)},
		{http.MethodPost, "/v1/verify", op("verify", http.MethodPost, "/v1/verify", "Verify subject", []string{app.ScopeVerifyRead}), http.HandlerFunc(s.verifySubject)},
		{http.MethodPost, "/v1/api-keys", op("createAPIKey", http.MethodPost, "/v1/api-keys", "Create API key", []string{app.ScopeAdmin}), http.HandlerFunc(s.createAPIKey)},
		{http.MethodGet, "/v1/api-keys", op("listAPIKeys", http.MethodGet, "/v1/api-keys", "List API keys", []string{app.ScopeAdmin}), http.HandlerFunc(s.listAPIKeys)},
	}
	for _, route := range routes {
		if err := s.routes.Register(routecontracts.Route{Method: route.method, Pattern: route.path, Handler: route.handler, Operation: route.op}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"version": "dev"})
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.OpenAPI()
	if err != nil {
		writeProblem(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Slug string }
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		product, err := s.ledger.CreateProduct(r.Context(), actor, req.Name, req.Slug)
		return http.StatusCreated, product, err
	})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	products, err := s.ledger.ListProducts(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, products)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		project, err := s.ledger.CreateProject(r.Context(), actor, req.ProductID, req.Name)
		return http.StatusCreated, project, err
	})
}

func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.ledger.CreateRelease(r.Context(), actor, req.ProductID, req.Version)
		return http.StatusCreated, release, err
	})
}

func (s *Server) getRelease(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	release, err := s.ledger.GetRelease(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, release)
}

func (s *Server) freezeRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		release, err := s.ledger.FreezeRelease(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, release, err
	})
}

func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		release, err := s.ledger.ApproveRelease(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, release, err
	})
}

func (s *Server) registerArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		MediaType string `json:"media_type"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		artifact, err := s.ledger.RegisterArtifact(r.Context(), actor, req.Name, req.MediaType, req.Digest, req.Size)
		return http.StatusCreated, artifact, err
	})
}

func (s *Server) createEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID        string              `json:"product_id"`
		ProjectID        string              `json:"project_id"`
		ReleaseID        string              `json:"release_id"`
		Type             string              `json:"type"`
		Subtype          string              `json:"subtype"`
		Title            string              `json:"title"`
		SourceSystem     string              `json:"source_system"`
		SourceIdentity   map[string]any      `json:"source_identity"`
		CollectorID      string              `json:"collector_id"`
		ObservedAt       time.Time           `json:"observed_at"`
		PayloadRef       string              `json:"payload_ref"`
		PayloadHash      string              `json:"payload_hash"`
		PayloadMediaType string              `json:"payload_media_type"`
		PayloadSize      int64               `json:"payload_size"`
		SubjectRefs      []domain.SubjectRef `json:"subject_refs"`
		Metadata         map[string]any      `json:"metadata"`
		Tags             []string            `json:"tags"`
		Limitations      []string            `json:"limitations"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.CreateEvidence(r.Context(), actor, app.CreateEvidenceInput{
			ProductID: req.ProductID, ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, Type: req.Type, Subtype: req.Subtype, Title: req.Title,
			SourceSystem: req.SourceSystem, SourceIdentity: req.SourceIdentity, CollectorID: req.CollectorID, ObservedAt: req.ObservedAt,
			PayloadRef: req.PayloadRef, PayloadHash: req.PayloadHash, PayloadMediaType: req.PayloadMediaType, PayloadSize: req.PayloadSize,
			SubjectRefs: req.SubjectRefs, Metadata: req.Metadata, Tags: req.Tags, Limitations: req.Limitations,
		})
		return http.StatusCreated, item, err
	})
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	items, err := s.ledger.ListEvidence(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("type"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, items)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	item, err := s.ledger.GetEvidence(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, item)
}

func (s *Server) supersedeEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReplacementEvidenceID string `json:"replacement_evidence_id"`
		Reason                string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.SupersedeEvidence(r.Context(), actor, r.PathValue("id"), req.ReplacementEvidenceID, req.Reason)
		return http.StatusCreated, item, err
	})
}

func (s *Server) linkEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.ledger.LinkEvidence(r.Context(), actor, r.PathValue("id"), req.TargetType, req.TargetID)
		return http.StatusCreated, item, err
	})
}

func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.ledger.UploadSBOM(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) getSBOM(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	sbom, err := s.ledger.GetSBOM(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sbom)
}

func (s *Server) uploadVEX(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.ledger.UploadVEX(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) getVEX(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	vex, err := s.ledger.GetVEXDocument(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, vex)
}

func (s *Server) uploadVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		scan, err := s.ledger.UploadVulnerabilityScan(r.Context(), actor, body)
		return http.StatusCreated, scan, err
	})
}

func (s *Server) getVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	scan, err := s.ledger.GetVulnerabilityScan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, scan)
}

func (s *Server) createVulnerabilityDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		decision, err := s.ledger.CreateVulnerabilityDecision(r.Context(), actor, r.PathValue("id"), app.CreateVulnerabilityDecisionInput{
			Status:          req.Status,
			Justification:   req.Justification,
			ImpactStatement: req.ImpactStatement,
			ActionStatement: req.ActionStatement,
		})
		return http.StatusCreated, decision, err
	})
}

func (s *Server) uploadOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string          `json:"product_id"`
		ReleaseID string          `json:"release_id"`
		Version   string          `json:"version"`
		Spec      json.RawMessage `json:"spec"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		contract, err := s.ledger.UploadOpenAPIContract(r.Context(), actor, req.ProductID, req.ReleaseID, req.Version, req.Spec)
		return http.StatusCreated, contract, err
	})
}

func (s *Server) getOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	contract, err := s.ledger.GetOpenAPIContract(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, contract)
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.ledger.EvaluateRelease(r.Context(), actor, req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) missingEvidenceReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.MissingEvidenceReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string    `json:"release_id"`
		FindingID string    `json:"finding_id"`
		ControlID string    `json:"control_id"`
		Reason    string    `json:"reason"`
		Owner     string    `json:"owner"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		exception, err := s.ledger.CreateException(r.Context(), actor, app.CreateExceptionInput{
			ReleaseID: req.ReleaseID,
			FindingID: req.FindingID,
			ControlID: req.ControlID,
			Reason:    req.Reason,
			Owner:     req.Owner,
			ExpiresAt: req.ExpiresAt,
		})
		return http.StatusCreated, exception, err
	})
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	exceptions, err := s.ledger.ListExceptions(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, exceptions)
}

func (s *Server) approveException(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(actor domain.Actor, _ []byte) (int, any, error) {
		exception, err := s.ledger.ApproveException(r.Context(), actor, r.PathValue("id"))
		return http.StatusOK, exception, err
	})
}

func (s *Server) releaseReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.ReleaseReadinessReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReleaseBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		bundle, err := s.ledger.CreateReleaseBundle(r.Context(), actor, req.ReleaseID)
		return http.StatusCreated, bundle, err
	})
}

func (s *Server) getReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle)
}

func (s *Server) getReleaseBundleManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle.Manifest)
}

func (s *Server) verifyReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifySubject(r.Context(), actor, "release_bundle", r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.ledger.VerifySubject(r.Context(), actor, "audit_chain", "")
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := s.ledger.ListSigningKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, keys)
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if len(bytes.TrimSpace(body)) > 0 {
			if err := decodeJSON(body, &req); err != nil {
				return 0, nil, err
			}
		}
		key, err := s.ledger.RotateSigningKey(r.Context(), actor, req.Reason)
		return http.StatusCreated, key, err
	})
}

func (s *Server) verifySubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		result, err := s.ledger.VerifySubject(r.Context(), actor, req.SubjectType, req.SubjectID)
		return http.StatusOK, result, err
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		key, secret, err := s.ledger.CreateAPIKey(r.Context(), actor, req.Name, req.Scopes, req.ExpiresAt)
		return http.StatusCreated, map[string]any{"api_key": key, "secret": secret}, err
	})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := s.ledger.ListAPIKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, keys)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, run func(domain.Actor, []byte) (int, any, error)) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status, response, err := s.ledger.WithIdempotency(r.Context(), actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), body, func() (int, any, error) {
		return run(actor, body)
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if r.Header.Get("Idempotency-Key") != "" {
		w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	}
	writeData(w, status, response)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	actor, err := s.ledger.Authenticate(r.Context(), strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if err != nil {
		writeProblem(w, r, err)
		return domain.Actor{}, false
	}
	return actor, true
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return nil, app.ErrValidation
	}
	if len(body) > maxJSONBody {
		return nil, app.ErrValidation
	}
	return body, nil
}

func decodeJSON(body []byte, out any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		trimmed = []byte(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return app.ErrValidation
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return app.ErrValidation
	}
	return nil
}

func writeData(w http.ResponseWriter, status int, data any) {
	httpx.WriteJSON(w, status, map[string]any{"data": data, "meta": map[string]string{"api_version": "v1"}})
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	status := app.StatusCode(err)
	problem := httpx.Problem{
		Type:   "https://evydence.local/problems/" + strings.ToLower(strings.ReplaceAll(app.ProblemCode(err), "_", "-")),
		Title:  http.StatusText(status),
		Detail: app.SafeErrorDetail(err),
		Ext: map[string]any{
			"code": app.ProblemCode(err),
		},
	}
	if r != nil {
		problem.Instance = r.URL.Path
	}
	httpx.WriteProblem(w, status, problem)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type serveMuxRouter struct {
	mux *http.ServeMux
}

func (r *serveMuxRouter) Get(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("GET "+pattern, h)
}

func (r *serveMuxRouter) Post(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("POST "+pattern, h)
}

func (r *serveMuxRouter) Put(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PUT "+pattern, h)
}

func (r *serveMuxRouter) Delete(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("DELETE "+pattern, h)
}

func (r *serveMuxRouter) Patch(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PATCH "+pattern, h)
}

func op(id, method, path, summary string, scopes []string) specs.Operation {
	operation := specs.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Tags:        []string{"evydence"},
		Responses: map[int]specs.Response{
			200: {Description: "OK"},
			201: {Description: "Created"},
			400: {Description: "Bad request"},
			401: {Description: "Unauthorized"},
			403: {Description: "Forbidden"},
			404: {Description: "Not found"},
			409: {Description: "Conflict"},
			422: {Description: "Verification failed"},
		},
	}
	if len(scopes) > 0 {
		operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
		operation.Scopes = scopes
	}
	if method == http.MethodPost {
		operation.Extensions = idempotent.OperationExtensions(true)
	}
	return operation
}
