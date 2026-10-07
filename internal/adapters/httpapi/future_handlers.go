package httpapi

import (
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) createEvidenceSummary(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.evidenceSummaryCommands != nil {
		s.createDurableEvidenceSummary(w, r)
		return
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeEvidenceSummaryRequest(body)
		if err != nil {
			return 0, nil, err
		}
		summary, err := s.ledger.CreateEvidenceSummary(ctx, actor, app.CreateEvidenceSummaryInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, EvidenceIDs: req.EvidenceIDs})
		return http.StatusCreated, summary, err
	})
}

func (s *Server) createQuestionnaireDraft(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.questionnaireDraftCommands != nil {
		s.createDurableQuestionnaireDraft(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeQuestionnaireDraftRequest(body)
		if err != nil {
			return 0, nil, err
		}
		draft, err := s.ledger.CreateQuestionnaireDraft(ctx, actor, app.CreateQuestionnaireDraftInput{TemplateID: req.TemplateID, ProductID: req.ProductID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, draft, err
	}, func(_ *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		return questionnaireDraftReplayFingerprint(a, body)
	})
}

func (s *Server) createGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurableGraphSnapshot(w, r)
}

func (s *Server) createSaaSEditionProfile(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurableSaaSProfile(w, r)
}

func (s *Server) createPublicTransparencyLog(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurablePublicTransparencyLog(w, r)
}

func (s *Server) publishPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.publishDurablePublicTransparencyLogEntry(w, r)
}

func (s *Server) verifyPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.verifyDurablePublicTransparencyLogEntry(w, r)
}

func (s *Server) fetchPublicTransparencyLogEntryProof(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.fetchDurablePublicTransparencyLogEntryProof(w, r)
}

func (s *Server) createMarketplaceCollector(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurableMarketplaceCollector(w, r)
}

func (s *Server) listMarketplaceCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	request, err := s.parsePageRequest(r, actor, "marketplace-collectors")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	result, err := s.marketplaceCollectorQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
	if err != nil {
		writeProblem(w, r, mapMarketplaceCollectorQueryError(err))
		return
	}
	page := appquery.Result[domain.MarketplaceCollector]{Next: result.Next, Items: make([]domain.MarketplaceCollector, 0, len(result.Items))}
	for _, collector := range result.Items {
		page.Items = append(page.Items, marketplaceCollectorFromQuery(collector))
	}
	writePage(s, w, r, actor, "marketplace-collectors", request, page)
}

func (s *Server) marketplaceCollectorHealth(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.marketplaceCollectorQuery.Health(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, mapMarketplaceCollectorQueryError(err))
		return
	}
	writeData(w, http.StatusOK, marketplaceCollectorHealthFromQuery(report))
}

func (s *Server) createPDFReportPackage(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurablePDFReportPackage(w, r)
}

func (s *Server) generateAnomalyReport(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.generateDurableAnomalyReport(w, r)
}

func (s *Server) createSigningOperation(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurableSigningOperation(w, r)
}

func (s *Server) verifyProviderIdentity(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.verifyDurableProviderIdentity(w, r)
}
