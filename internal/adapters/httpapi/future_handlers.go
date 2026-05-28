package httpapi

import (
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) createEvidenceSummary(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string   `json:"subject_type"`
		SubjectID   string   `json:"subject_id"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		summary, err := s.ledger.CreateEvidenceSummary(ctx, actor, app.CreateEvidenceSummaryInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, EvidenceIDs: req.EvidenceIDs})
		return http.StatusCreated, summary, err
	})
}

func (s *Server) createQuestionnaireDraft(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string `json:"template_id"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		draft, err := s.ledger.CreateQuestionnaireDraft(ctx, actor, app.CreateQuestionnaireDraftInput{TemplateID: req.TemplateID, ProductID: req.ProductID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, draft, err
	})
}

func (s *Server) createGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		graph, err := s.ledger.CreateGraphSnapshot(ctx, actor, app.CreateGraphSnapshotInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, graph, err
	})
}

func (s *Server) createSaaSEditionProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string `json:"name"`
		Region         string `json:"region"`
		AdminTenantID  string `json:"admin_tenant_id"`
		IsolationModel string `json:"isolation_model"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		profile, err := s.ledger.CreateSaaSEditionProfile(ctx, actor, app.CreateSaaSEditionProfileInput{Name: req.Name, Region: req.Region, AdminTenantID: req.AdminTenantID, IsolationModel: req.IsolationModel})
		return http.StatusCreated, profile, err
	})
}

func (s *Server) createPublicTransparencyLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Endpoint  string `json:"endpoint"`
		PublicKey string `json:"public_key"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		log, err := s.ledger.CreatePublicTransparencyLog(ctx, actor, app.CreatePublicTransparencyLogInput{Name: req.Name, Endpoint: req.Endpoint, PublicKey: req.PublicKey})
		return http.StatusCreated, log, err
	})
}

func (s *Server) publishPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LogID        string `json:"log_id"`
		CheckpointID string `json:"checkpoint_id"`
		ExternalID   string `json:"external_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		entry, err := s.ledger.PublishPublicTransparencyLogEntry(ctx, actor, app.PublishPublicTransparencyLogEntryInput{LogID: req.LogID, CheckpointID: req.CheckpointID, ExternalID: req.ExternalID})
		return http.StatusCreated, entry, err
	})
}

func (s *Server) verifyPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeafHash       string   `json:"leaf_hash"`
		RootHash       string   `json:"root_hash"`
		LeafIndex      int      `json:"leaf_index"`
		TreeSize       int      `json:"tree_size"`
		InclusionProof []string `json:"inclusion_proof"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		entry, err := s.ledger.VerifyPublicTransparencyLogEntry(ctx, actor, r.PathValue("id"), app.VerifyPublicTransparencyLogEntryInput{
			LeafHash:       req.LeafHash,
			RootHash:       req.RootHash,
			LeafIndex:      req.LeafIndex,
			TreeSize:       req.TreeSize,
			InclusionProof: req.InclusionProof,
		})
		return http.StatusOK, entry, err
	})
}

func (s *Server) createMarketplaceCollector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Provider     string `json:"provider"`
		Version      string `json:"version"`
		Publisher    string `json:"publisher"`
		ManifestHash string `json:"manifest_hash"`
		SignatureID  string `json:"signature_id"`
		SBOMID       string `json:"sbom_id"`
		ScanID       string `json:"scan_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		collector, err := s.ledger.CreateMarketplaceCollector(ctx, actor, app.CreateMarketplaceCollectorInput{Name: req.Name, Provider: req.Provider, Version: req.Version, Publisher: req.Publisher, ManifestHash: req.ManifestHash, SignatureID: req.SignatureID, SBOMID: req.SBOMID, ScanID: req.ScanID})
		return http.StatusCreated, collector, err
	})
}

func (s *Server) listMarketplaceCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	collectors, err := s.ledger.ListMarketplaceCollectors(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, collectors)
}

func (s *Server) marketplaceCollectorHealth(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.MarketplaceCollectorHealth(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createPDFReportPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReportType string `json:"report_type"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
		Title      string `json:"title"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pkg, err := s.ledger.CreatePDFReportPackage(ctx, actor, app.CreatePDFReportPackageInput{ReportType: req.ReportType, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title})
		return http.StatusCreated, pkg, err
	})
}

func (s *Server) generateAnomalyReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		report, err := s.ledger.GenerateAnomalyReport(ctx, actor, app.AnomalyReportInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID})
		return http.StatusCreated, report, err
	})
}

func (s *Server) createSigningOperation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID        string `json:"provider_id"`
		SubjectType       string `json:"subject_type"`
		SubjectID         string `json:"subject_id"`
		PayloadHash       string `json:"payload_hash"`
		ExternalSignature string `json:"external_signature"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		op, err := s.ledger.CreateSigningOperation(ctx, actor, app.CreateSigningOperationInput{ProviderID: req.ProviderID, SubjectType: req.SubjectType, SubjectID: req.SubjectID, PayloadHash: req.PayloadHash, ExternalSignature: req.ExternalSignature})
		return http.StatusCreated, op, err
	})
}

func (s *Server) verifyProviderIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderType  string `json:"provider_type"`
		ProviderID    string `json:"provider_id"`
		Subject       string `json:"subject"`
		IDToken       string `json:"id_token"`
		SAMLAssertion string `json:"saml_assertion"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.VerifyProviderIdentity(ctx, actor, app.VerifyProviderIdentityInput{ProviderType: req.ProviderType, ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion})
		return http.StatusCreated, record, err
	})
}
