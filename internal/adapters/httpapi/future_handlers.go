package httpapi

import (
	"net/http"
	"time"

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
	if s.graphSnapshotCommands != nil {
		s.createDurableGraphSnapshot(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeGraphSnapshotRequest(body)
		if err != nil {
			return 0, nil, err
		}
		graph, err := s.ledger.CreateGraphSnapshot(ctx, actor, app.CreateGraphSnapshotInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, graph, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodeGraphSnapshotRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreateGraphSnapshot(r.Context(), a, app.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) createSaaSEditionProfile(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.saasProfileCommands != nil {
		s.createDurableSaaSProfile(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeSaaSProfileRequest(body)
		if err != nil {
			return 0, nil, err
		}
		profile, err := s.ledger.CreateSaaSEditionProfile(ctx, actor, app.CreateSaaSEditionProfileInput{Name: req.Name, Region: req.Region, AdminTenantID: req.AdminTenantID, IsolationModel: req.IsolationModel})
		return http.StatusCreated, profile, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodeSaaSProfileRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreateSaaSEditionProfile(r.Context(), a, app.CreateSaaSEditionProfileInput{Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel}); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) createPublicTransparencyLog(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.publicTransparencyMetadata != nil {
		s.createDurablePublicTransparencyLog(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodePublicTransparencyLog(body)
		if err != nil {
			return 0, nil, err
		}
		log, err := s.ledger.CreatePublicTransparencyLog(ctx, actor, legacyPublicTransparencyLogInput(req))
		return http.StatusCreated, log, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodePublicTransparencyLog(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreatePublicTransparencyLog(r.Context(), a, legacyPublicTransparencyLogInput(in)); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) publishPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.publicTransparencyMetadata != nil {
		s.publishDurablePublicTransparencyLogEntry(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodePublicTransparencyPublication(body)
		if err != nil {
			return 0, nil, err
		}
		entry, err := s.ledger.PublishPublicTransparencyLogEntry(ctx, actor, legacyPublicTransparencyPublicationInput(req))
		return http.StatusCreated, entry, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodePublicTransparencyPublication(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizePublishPublicTransparencyLogEntry(r.Context(), a, legacyPublicTransparencyPublicationInput(in)); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) verifyPublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.publicTransparencyProofs != nil {
		s.verifyDurablePublicTransparencyLogEntry(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		in, err := decodePublicTransparencyProof(body, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		v, err := s.ledger.VerifyPublicTransparencyLogEntry(ctx, actor, r.PathValue("id"), legacyPublicTransparencyProofInput(in))
		return http.StatusOK, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodePublicTransparencyProof(body, r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeVerifyPublicTransparencyLogEntry(r.Context(), a, r.PathValue("id"), legacyPublicTransparencyProofInput(in)); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) fetchPublicTransparencyLogEntryProof(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.publicTransparencyFetch != nil {
		s.fetchDurablePublicTransparencyLogEntryProof(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodePublicTransparencyFetch(body, r.PathValue("id")); err != nil {
			return 0, nil, err
		}
		entry, err := s.ledger.FetchAndVerifyPublicTransparencyLogEntry(ctx, actor, r.PathValue("id"))
		return http.StatusOK, entry, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := decodePublicTransparencyFetch(body, r.PathValue("id")); err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeFetchPublicTransparencyLogEntryProof(r.Context(), a, r.PathValue("id")); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) createMarketplaceCollector(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.marketplaceCollectorCommands != nil {
		s.createDurableMarketplaceCollector(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeMarketplaceCollectorRequest(body)
		if err != nil {
			return 0, nil, err
		}
		collector, err := s.ledger.CreateMarketplaceCollector(ctx, actor, marketplaceCollectorLegacyInput(req))
		return http.StatusCreated, collector, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodeMarketplaceCollectorRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreateMarketplaceCollector(r.Context(), a, marketplaceCollectorLegacyInput(in)); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) listMarketplaceCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.marketplaceCollectorQuery != nil {
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
		return
	}
	collectors, err := s.ledger.ListMarketplaceCollectors(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "marketplace-collectors", nil, collectors, func(collector domain.MarketplaceCollector) (string, time.Time) {
		return collector.ID, collector.CreatedAt
	})
}

func (s *Server) marketplaceCollectorHealth(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.marketplaceCollectorQuery != nil {
		report, err := s.marketplaceCollectorQuery.Health(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapMarketplaceCollectorQueryError(err))
			return
		}
		writeData(w, http.StatusOK, marketplaceCollectorHealthFromQuery(report))
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
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.pdfReportCommands != nil {
		s.createDurablePDFReportPackage(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodePDFReportRequest(body)
		if err != nil {
			return 0, nil, err
		}
		pkg, err := s.ledger.CreatePDFReportPackage(ctx, actor, app.CreatePDFReportPackageInput{ReportType: req.ReportType, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title})
		return http.StatusCreated, pkg, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodePDFReportRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreatePDFReportPackage(r.Context(), a, app.CreatePDFReportPackageInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title}); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) generateAnomalyReport(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.anomalyReportCommands != nil {
		s.generateDurableAnomalyReport(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeAnomalyReportRequest(body)
		if err != nil {
			return 0, nil, err
		}
		report, err := s.ledger.GenerateAnomalyReport(ctx, actor, app.AnomalyReportInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID})
		return http.StatusCreated, report, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodeAnomalyReportRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeGenerateAnomalyReport(r.Context(), a, app.AnomalyReportInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID}); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) createSigningOperation(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.signingOperationCommands != nil {
		s.createDurableSigningOperation(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeSigningOperationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		op, err := s.ledger.CreateSigningOperation(ctx, actor, app.CreateSigningOperationInput{ProviderID: req.ProviderID, SubjectType: req.SubjectType, SubjectID: req.SubjectID, PayloadHash: req.PayloadHash})
		return http.StatusCreated, op, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		in, err := decodeSigningOperationRequest(body)
		if err != nil {
			return nil, err
		}
		if err := s.ledger.AuthorizeCreateSigningOperation(r.Context(), a, app.CreateSigningOperationInput{ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash}); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) verifyProviderIdentity(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.providerVerificationCommands != nil {
		s.verifyDurableProviderIdentity(w, r)
		return
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeProviderVerificationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.VerifyProviderIdentity(ctx, actor, app.VerifyProviderIdentityInput{ProviderType: req.ProviderType, ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion, AccessToken: req.AccessToken})
		return http.StatusCreated, record, err
	})
}
