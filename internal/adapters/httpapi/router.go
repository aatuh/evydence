package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"
	"github.com/aatuh/api-toolkit/v3/idempotent"
	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type requestContext = context.Context

const requestIDHeader = "X-Request-ID"

type Server struct {
	ledger            *app.Ledger
	authn             Authenticator
	idempotency       idempotencyExecutor
	identityAccess    identityAccessService
	releaseCatalog    releaseCatalogService
	productQuery      ProductQuery
	catalogPointQuery CatalogPointQuery
	evidenceIngestion evidenceIngestionService
	riskDecisions     riskDecisionService
	packages          packageService
	verification      verificationService
	mux               *http.ServeMux
	specs             *specs.Registry
	routes            *routecontracts.Registry
	ingress           *ingressControl
	identity          runtimeinfo.Identity
	cursors           appquery.CursorCodec
}

type ServerOptions struct {
	// RateLimitRequestsPerMinute bounds unauthenticated and authenticated edge
	// traffic by client address. Forwarded addresses are used only when the
	// direct remote address belongs to TrustedProxyCIDRs.
	RateLimitRequestsPerMinute int
	// ExpensiveTenantRequestsPerMinute bounds storage, parsing, export, and
	// report-heavy POST operations per authenticated tenant and route.
	ExpensiveTenantRequestsPerMinute int
	RateLimitBucketCapacity          int
	TrustedProxyCIDRs                []string
	MaxURLBytes                      int
	MaxInboundRequestBytes           int64
	MaxInFlightRequests              int
	MaxConcurrentUploads             int
	BuildIdentity                    runtimeinfo.Identity
	// Authenticator overrides the local-memory Ledger authentication adapter.
	// Production binds it to current PostgreSQL credential and grant rows.
	Authenticator Authenticator
	// PaginationSecret authenticates opaque cursor tokens. Production callers
	// should supply a stable, non-public secret so tokens survive restarts.
	PaginationSecret []byte
	// ProductQuery enables bounded PostgreSQL-backed catalog reads.
	// Local-memory servers retain the legacy in-process query path.
	ProductQuery ProductQuery
	// CatalogPointQuery enables tenant-filtered PostgreSQL project/release
	// reads. Local-memory servers use the compatibility service instead.
	CatalogPointQuery CatalogPointQuery
}

func NewServer(ledger *app.Ledger) (*Server, error) {
	return NewServerWithOptionsContext(context.Background(), ledger, ServerOptions{})
}

func NewServerWithOptions(ledger *app.Ledger, opts ServerOptions) (*Server, error) {
	return NewServerWithOptionsContext(context.Background(), ledger, opts)
}

func NewServerWithOptionsContext(ctx context.Context, ledger *app.Ledger, opts ServerOptions) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("server context is required")
	}
	if ledger == nil {
		var err error
		ledger, err = app.NewLedgerWithContext(ctx, app.Config{})
		if err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	specRegistry := NewSpecRegistry()
	router := &serveMuxRouter{mux: mux}
	routeRegistry := routecontracts.NewRegistry(router, specRegistry)
	identity := opts.BuildIdentity
	if identity.IsZero() {
		identity = runtimeinfo.Current()
	}
	paginationSecret := opts.PaginationSecret
	if len(paginationSecret) == 0 {
		paginationSecret = make([]byte, 32)
		if _, err := rand.Read(paginationSecret); err != nil {
			return nil, err
		}
	}
	cursors, err := appquery.NewCursorCodec(paginationSecret)
	if err != nil {
		return nil, err
	}
	ingress, err := newIngressControl(opts)
	if err != nil {
		return nil, err
	}
	server := &Server{mux: mux, specs: specRegistry, routes: routeRegistry, ingress: ingress, identity: identity, cursors: cursors, productQuery: opts.ProductQuery, catalogPointQuery: opts.CatalogPointQuery}
	server.bindLedger(ledger)
	if opts.Authenticator != nil {
		server.authn = opts.Authenticator
	}
	if err := server.registerRoutes(); err != nil {
		return nil, err
	}
	return server, nil
}

// bindLedger updates both the shrinking compatibility facade and every
// context-specific transport dependency. Idempotent commands must bind the
// isolated command ledger so domain changes and the replay record share the
// same transaction and are published only after commit.
func (s *Server) bindLedger(ledger *app.Ledger) {
	s.ledger = ledger
	s.authn = ledger
	s.idempotency = ledgerIdempotencyExecutor{ledger: ledger}
	s.identityAccess = ledger
	s.releaseCatalog = ledger
	s.evidenceIngestion = ledger
	s.riskDecisions = ledger
	s.packages = ledger
	s.verification = ledger
}

func (s *Server) Handler() http.Handler {
	return secureHeaders(requestIDMiddleware(s.inFlightMiddleware(s.ingressValidationMiddleware(s.rateLimitMiddleware(s.uploadConcurrencyMiddleware(s.conditionalReadMiddleware(s.mux)))))))
}

func (s *Server) OpenAPI() ([]byte, error) {
	return s.specs.OpenAPI()
}

func (s *Server) ValidateRoutes() error {
	return s.routes.Validate()
}

func (s *Server) createCollector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		Version string   `json:"version"`
		Scopes  []string `json:"scopes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		collector, key, secret, err := s.ledger.CreateCollector(ctx, actor, app.CreateCollectorInput{
			Name:    req.Name,
			Type:    req.Type,
			Version: req.Version,
			Scopes:  req.Scopes,
		})
		return http.StatusCreated, map[string]any{"collector": collector, "api_key": key, "secret": secret}, err
	})
}

func (s *Server) listCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	collectors, err := s.ledger.ListCollectors(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "collectors", nil, collectors, func(collector domain.Collector) (string, time.Time) {
		return collector.ID, collector.CreatedAt
	})
}

func (s *Server) recordCollectorRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version        string `json:"version"`
		ArtifactDigest string `json:"artifact_digest"`
		SignatureID    string `json:"signature_id"`
		SBOMID         string `json:"sbom_id"`
		ScanID         string `json:"scan_id"`
		Pinned         bool   `json:"pinned"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.ledger.RecordCollectorRelease(ctx, actor, app.RecordCollectorReleaseInput{
			CollectorID:    r.PathValue("id"),
			Version:        req.Version,
			ArtifactDigest: req.ArtifactDigest,
			SignatureID:    req.SignatureID,
			SBOMID:         req.SBOMID,
			ScanID:         req.ScanID,
			Pinned:         req.Pinned,
		})
		return http.StatusCreated, release, err
	})
}

func (s *Server) collectorHealthReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CollectorHealthReport(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createControlFramework(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Version     string `json:"version"`
		Description string `json:"description"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		framework, err := s.ledger.CreateControlFramework(ctx, actor, app.CreateControlFrameworkInput{
			Name:        req.Name,
			Slug:        req.Slug,
			Version:     req.Version,
			Description: req.Description,
		})
		return http.StatusCreated, framework, err
	})
}

func (s *Server) listControlFrameworks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	frameworks, err := s.ledger.ListControlFrameworks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "control-frameworks", nil, frameworks, func(framework domain.ControlFramework) (string, time.Time) {
		return framework.ID, framework.CreatedAt
	})
}

func (s *Server) listControlFrameworkTemplatePacks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	packs, err := s.ledger.ListControlFrameworkTemplatePacks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePaginated(s, w, r, actor, "control-framework-template-packs", nil, packs, func(pack domain.ControlFrameworkTemplatePack, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(pack.ID, time.Time{}, sort)
	})
}

func (s *Server) installControlFrameworkTemplatePack(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		framework, err := s.ledger.InstallControlFrameworkTemplatePack(ctx, actor, r.PathValue("slug"))
		return http.StatusCreated, framework, err
	})
}

func (s *Server) createSecurityControl(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FrameworkID          string                              `json:"framework_id"`
		Code                 string                              `json:"code"`
		Title                string                              `json:"title"`
		Objective            string                              `json:"objective"`
		EvidenceRequirements []domain.ControlEvidenceRequirement `json:"evidence_requirements"`
		Applicability        []string                            `json:"applicability"`
		Limitations          []string                            `json:"limitations"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		control, err := s.ledger.CreateSecurityControl(ctx, actor, app.CreateSecurityControlInput{
			FrameworkID:          req.FrameworkID,
			Code:                 req.Code,
			Title:                req.Title,
			Objective:            req.Objective,
			EvidenceRequirements: req.EvidenceRequirements,
			Applicability:        req.Applicability,
			Limitations:          req.Limitations,
		})
		return http.StatusCreated, control, err
	})
}

func (s *Server) getSecurityControl(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	control, err := s.ledger.GetSecurityControl(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, control)
}

func (s *Server) linkControlEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EvidenceType string `json:"evidence_type"`
		SubjectType  string `json:"subject_type"`
		SubjectID    string `json:"subject_id"`
		ProductID    string `json:"product_id"`
		ReleaseID    string `json:"release_id"`
		Confidence   string `json:"confidence"`
		Notes        string `json:"notes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		link, err := s.ledger.LinkControlEvidence(ctx, actor, r.PathValue("id"), app.LinkControlEvidenceInput{
			EvidenceType: req.EvidenceType,
			SubjectType:  req.SubjectType,
			SubjectID:    req.SubjectID,
			ProductID:    req.ProductID,
			ReleaseID:    req.ReleaseID,
			Confidence:   req.Confidence,
			Notes:        req.Notes,
		})
		return http.StatusCreated, link, err
	})
}

func (s *Server) listControlEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	links, err := s.ledger.ListControlEvidence(r.Context(), actor, r.URL.Query().Get("control_id"), r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "control-evidence", []string{"control_id", "product_id", "release_id"}, links, func(link domain.ControlEvidence) (string, time.Time) {
		return link.ID, link.CreatedAt
	})
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Slug string }
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		product, err := s.releaseCatalog.CreateProduct(ctx, actor, req.Name, req.Slug)
		return http.StatusCreated, product, err
	})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.productQuery != nil {
		request, err := s.parsePageRequest(r, actor, "products")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.productQuery.ListProductsPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			switch {
			case errors.Is(err, releasequery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
				err = app.ErrValidation
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		mapped := appquery.Result[domain.Product]{Next: page.Next, Items: make([]domain.Product, 0, len(page.Items))}
		for _, product := range page.Items {
			mapped.Items = append(mapped.Items, domain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt})
		}
		writePage(s, w, r, actor, "products", request, mapped)
		return
	}
	products, err := s.releaseCatalog.ListProducts(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "products", nil, products, func(product domain.Product) (string, time.Time) {
		return product.ID, product.CreatedAt
	})
}

func (s *Server) getProduct(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.productQuery != nil {
		product, err := s.productQuery.GetProduct(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			switch {
			case errors.Is(err, releasequery.ErrValidation):
				err = app.ErrValidation
			case errors.Is(err, releasequery.ErrNotFound):
				err = app.ErrNotFound
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		writeData(w, http.StatusOK, domain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt})
		return
	}
	product, err := s.releaseCatalog.GetProduct(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, product)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		project, err := s.releaseCatalog.CreateProject(ctx, actor, req.ProductID, req.Name)
		return http.StatusCreated, project, err
	})
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.catalogPointQuery != nil {
		project, err := s.catalogPointQuery.GetProject(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.Project{ID: project.ID, TenantID: project.TenantID, ProductID: project.ProductID, Name: project.Name, CreatedAt: project.CreatedAt})
		return
	}
	project, err := s.releaseCatalog.GetProject(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, project)
}

func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.releaseCatalog.CreateRelease(ctx, actor, req.ProductID, req.Version)
		return http.StatusCreated, release, err
	})
}

func (s *Server) getRelease(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.catalogPointQuery != nil {
		release, err := s.catalogPointQuery.GetRelease(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.ReleaseFromContextModel(release))
		return
	}
	release, err := s.releaseCatalog.GetRelease(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, release)
}

func mapCatalogPointQueryError(err error) error {
	switch {
	case errors.Is(err, releasequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, releasequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

func (s *Server) startReleaseEvidenceFlow(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	flow, err := s.releaseCatalog.ReleaseEvidenceFlowPlan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, flow)
}

func (s *Server) releaseSecuritySummary(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	summary, err := s.ledger.ReleaseSecuritySummary(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, summary)
}

func (s *Server) freezeRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		release, err := s.releaseCatalog.FreezeRelease(ctx, actor, r.PathValue("id"), expectedRevision)
		return http.StatusOK, release, err
	})
}

func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		release, err := s.releaseCatalog.ApproveRelease(ctx, actor, r.PathValue("id"), expectedRevision)
		return http.StatusOK, release, err
	})
}

func (s *Server) createReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		Name        string   `json:"name"`
		BuildIDs    []string `json:"build_ids"`
		ArtifactIDs []string `json:"artifact_ids"`
		SBOMIDs     []string `json:"sbom_ids"`
		ScanIDs     []string `json:"scan_ids"`
		VEXIDs      []string `json:"vex_ids"`
		ContractIDs []string `json:"contract_ids"`
		BundleIDs   []string `json:"bundle_ids"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		candidate, err := s.releaseCatalog.CreateReleaseCandidate(ctx, actor, app.CreateReleaseCandidateInput{
			ReleaseID: req.ReleaseID, Name: req.Name, BuildIDs: req.BuildIDs, ArtifactIDs: req.ArtifactIDs,
			SBOMIDs: req.SBOMIDs, ScanIDs: req.ScanIDs, VEXIDs: req.VEXIDs, ContractIDs: req.ContractIDs, BundleIDs: req.BundleIDs,
		})
		return http.StatusCreated, candidate, err
	})
}

func (s *Server) listReleaseCandidates(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	candidates, err := s.releaseCatalog.ListReleaseCandidates(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "release-candidates", []string{"release_id"}, candidates, func(candidate domain.ReleaseCandidate) (string, time.Time) {
		return candidate.ID, candidate.CreatedAt
	})
}

func (s *Server) getReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	candidate, err := s.releaseCatalog.GetReleaseCandidate(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, candidate)
}

func (s *Server) promoteReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "promoted")
}

func (s *Server) rejectReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "rejected")
}

func (s *Server) transitionReleaseCandidate(w http.ResponseWriter, r *http.Request, state string) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		candidate, err := s.releaseCatalog.UpdateReleaseCandidateState(ctx, actor, r.PathValue("id"), state, req.Reason, expectedRevision)
		return http.StatusOK, candidate, err
	})
}

func (s *Server) registerArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		MediaType string `json:"media_type"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		artifact, err := s.releaseCatalog.RegisterArtifact(ctx, actor, req.Name, req.MediaType, req.Digest, req.Size)
		return http.StatusCreated, artifact, err
	})
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	artifact, err := s.releaseCatalog.GetArtifact(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, artifact)
}

func (s *Server) registerContainerImage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID string `json:"artifact_id"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Digest     string `json:"digest"`
		Platform   string `json:"platform"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		image, err := s.releaseCatalog.RegisterContainerImage(ctx, actor, app.RegisterContainerImageInput{
			ArtifactID: req.ArtifactID, Repository: req.Repository, Tag: req.Tag, Digest: req.Digest, Platform: req.Platform,
		})
		return http.StatusCreated, image, err
	})
}

func (s *Server) createArtifactSignature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID       string          `json:"artifact_id"`
		Algorithm        string          `json:"algorithm"`
		KeyID            string          `json:"key_id"`
		Signature        string          `json:"signature"`
		Payload          json.RawMessage `json:"payload"`
		PayloadMediaType string          `json:"payload_media_type"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sig, err := s.ledger.CreateArtifactSignature(ctx, actor, app.CreateArtifactSignatureInput{
			ArtifactID: req.ArtifactID, Algorithm: req.Algorithm, KeyID: req.KeyID, Signature: req.Signature,
			RawPayload: req.Payload, PayloadMediaType: req.PayloadMediaType,
		})
		return http.StatusCreated, sig, err
	})
}

func (s *Server) getArtifactSignature(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	sig, err := s.ledger.GetArtifactSignature(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sig)
}

func (s *Server) verifyCosignSignature(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpectedIdentity string `json:"expected_identity"`
		ExpectedIssuer   string `json:"expected_issuer"`
		Mode             string `json:"mode"`
		Offline          bool   `json:"offline"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		result, err := s.verification.VerifyCosignSignature(ctx, actor, app.VerifyCosignInput{
			ArtifactSignatureID: r.PathValue("id"),
			ExpectedIdentity:    req.ExpectedIdentity,
			ExpectedIssuer:      req.ExpectedIssuer,
			Mode:                app.CosignVerificationMode(req.Mode),
			Offline:             req.Offline,
		})
		return http.StatusOK, result, err
	})
}

func (s *Server) createBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID        string               `json:"project_id"`
		ReleaseID        string               `json:"release_id"`
		Provider         string               `json:"provider"`
		CommitSHA        string               `json:"commit_sha"`
		Repository       string               `json:"repository"`
		WorkflowRef      string               `json:"workflow_ref"`
		RunID            string               `json:"run_id"`
		RunAttempt       int                  `json:"run_attempt"`
		JobID            string               `json:"job_id"`
		GitHubActor      string               `json:"actor"`
		Ref              string               `json:"ref"`
		OIDCSubject      string               `json:"oidc_subject"`
		Status           string               `json:"status"`
		StartedAt        time.Time            `json:"started_at"`
		FinishedAt       *time.Time           `json:"finished_at"`
		ParametersHash   string               `json:"parameters_hash"`
		EnvironmentHash  string               `json:"environment_hash"`
		ProviderMetadata map[string]any       `json:"provider_metadata"`
		Outputs          []domain.BuildOutput `json:"outputs"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		build, err := s.releaseCatalog.CreateBuildRun(ctx, actor, app.CreateBuildRunInput{
			ProjectID:        req.ProjectID,
			ReleaseID:        req.ReleaseID,
			Provider:         req.Provider,
			CommitSHA:        req.CommitSHA,
			Repository:       req.Repository,
			WorkflowRef:      req.WorkflowRef,
			RunID:            req.RunID,
			RunAttempt:       req.RunAttempt,
			JobID:            req.JobID,
			GitHubActor:      req.GitHubActor,
			Ref:              req.Ref,
			OIDCSubject:      req.OIDCSubject,
			Status:           req.Status,
			StartedAt:        req.StartedAt,
			FinishedAt:       req.FinishedAt,
			ParametersHash:   req.ParametersHash,
			EnvironmentHash:  req.EnvironmentHash,
			ProviderMetadata: req.ProviderMetadata,
			Outputs:          req.Outputs,
		})
		return http.StatusCreated, build, err
	})
}

func (s *Server) getBuild(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	build, err := s.releaseCatalog.GetBuildRun(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, build)
}

func (s *Server) uploadBuildAttestation(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		attestation, err := s.releaseCatalog.UploadBuildAttestation(ctx, actor, r.PathValue("id"), body)
		return http.StatusCreated, attestation, err
	})
}

func (s *Server) verifyBuildAttestationSignature(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		result, err := s.verification.VerifyDSSEAttestationSignature(ctx, actor, r.PathValue("id"))
		return http.StatusOK, result, err
	})
}

func (s *Server) createDSSETrustRoot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                  string   `json:"name"`
		KeyID                 string   `json:"key_id"`
		Algorithm             string   `json:"algorithm"`
		PublicKey             string   `json:"public_key"`
		AllowedPredicateTypes []string `json:"allowed_predicate_types"`
		ExpectedBuilderIDs    []string `json:"expected_builder_ids"`
		RequiredClaims        []string `json:"required_claims"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		root, err := s.verification.CreateDSSETrustRoot(ctx, actor, app.CreateDSSETrustRootInput{Name: req.Name, KeyID: req.KeyID, Algorithm: req.Algorithm, PublicKey: req.PublicKey, AllowedPredicateTypes: req.AllowedPredicateTypes, ExpectedBuilderIDs: req.ExpectedBuilderIDs, RequiredClaims: req.RequiredClaims})
		return http.StatusCreated, root, err
	})
}

func (s *Server) createSourceRepository(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID     string `json:"project_id"`
		Provider      string `json:"provider"`
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		repo, err := s.ledger.CreateSourceRepository(ctx, actor, app.CreateRepositoryInput{
			ProjectID: req.ProjectID, Provider: req.Provider, FullName: req.FullName, CloneURL: req.CloneURL, DefaultBranch: req.DefaultBranch,
		})
		return http.StatusCreated, repo, err
	})
}

func (s *Server) listSourceRepositories(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	repos, err := s.ledger.ListSourceRepositories(r.Context(), actor, r.URL.Query().Get("project_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "source-repositories", []string{"project_id"}, repos, func(repo domain.SourceRepository) (string, time.Time) {
		return repo.ID, repo.CreatedAt
	})
}

func (s *Server) recordSourceCommit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID string    `json:"repository_id"`
		SHA          string    `json:"sha"`
		Author       string    `json:"author"`
		Message      string    `json:"message"`
		CommittedAt  time.Time `json:"committed_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		commit, err := s.ledger.RecordSourceCommit(ctx, actor, app.RecordCommitInput{
			RepositoryID: req.RepositoryID, SHA: req.SHA, Author: req.Author, Message: req.Message, CommittedAt: req.CommittedAt,
		})
		return http.StatusCreated, commit, err
	})
}

func (s *Server) upsertSourceBranch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Name           string `json:"name"`
		HeadCommitID   string `json:"head_commit_id"`
		Protected      bool   `json:"protected"`
		ProtectionHash string `json:"protection_hash"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		branch, err := s.ledger.UpsertSourceBranch(ctx, actor, app.UpsertBranchInput{
			RepositoryID: req.RepositoryID, Name: req.Name, HeadCommitID: req.HeadCommitID, Protected: req.Protected, ProtectionHash: req.ProtectionHash,
		})
		return http.StatusCreated, branch, err
	})
}

func (s *Server) recordPullRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepositoryID   string `json:"repository_id"`
		Provider       string `json:"provider"`
		ProviderID     string `json:"provider_id"`
		Title          string `json:"title"`
		State          string `json:"state"`
		SourceBranch   string `json:"source_branch"`
		TargetBranch   string `json:"target_branch"`
		HeadCommitID   string `json:"head_commit_id"`
		ReviewDecision string `json:"review_decision"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pr, err := s.ledger.RecordPullRequest(ctx, actor, app.RecordPullRequestInput{
			RepositoryID: req.RepositoryID, Provider: req.Provider, ProviderID: req.ProviderID, Title: req.Title, State: req.State,
			SourceBranch: req.SourceBranch, TargetBranch: req.TargetBranch, HeadCommitID: req.HeadCommitID, ReviewDecision: req.ReviewDecision,
		})
		return http.StatusCreated, pr, err
	})
}

func (s *Server) uploadGitHubSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		result, err := s.ledger.UploadGitHubSourceSnapshot(ctx, actor, body)
		return http.StatusCreated, result, err
	})
}

func (s *Server) uploadGitLabSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		result, err := s.ledger.UploadGitLabSourceSnapshot(ctx, actor, body)
		return http.StatusCreated, result, err
	})
}

func (s *Server) createDeploymentEnvironment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		env, err := s.ledger.CreateDeploymentEnvironment(ctx, actor, app.CreateEnvironmentInput{ProductID: req.ProductID, Name: req.Name, Kind: req.Kind})
		return http.StatusCreated, env, err
	})
}

func (s *Server) listDeploymentEnvironments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	envs, err := s.ledger.ListDeploymentEnvironments(r.Context(), actor, r.URL.Query().Get("product_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "deployment-environments", []string{"product_id"}, envs, func(environment domain.DeploymentEnvironment) (string, time.Time) {
		return environment.ID, environment.CreatedAt
	})
}

func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnvironmentID string     `json:"environment_id"`
		ReleaseID     string     `json:"release_id"`
		ArtifactIDs   []string   `json:"artifact_ids"`
		Status        string     `json:"status"`
		StartedAt     time.Time  `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
		RollbackOf    string     `json:"rollback_of"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		deployment, err := s.ledger.RecordDeployment(ctx, actor, app.RecordDeploymentInput{
			EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ArtifactIDs: req.ArtifactIDs,
			Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, RollbackOf: req.RollbackOf,
		})
		return http.StatusCreated, deployment, err
	})
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	deployments, err := s.ledger.ListDeployments(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("environment_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "deployments", []string{"release_id", "environment_id"}, deployments, func(deployment domain.DeploymentEvent) (string, time.Time) {
		return deployment.ID, deployment.CreatedAt
	})
}

func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	deployment, err := s.ledger.GetDeployment(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, deployment)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string    `json:"product_id"`
		ReleaseID string    `json:"release_id"`
		Title     string    `json:"title"`
		Severity  string    `json:"severity"`
		OpenedAt  time.Time `json:"opened_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		incident, err := s.ledger.CreateIncident(ctx, actor, app.CreateIncidentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title, Severity: req.Severity, OpenedAt: req.OpenedAt})
		return http.StatusCreated, incident, err
	})
}

func (s *Server) recordIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventType  string    `json:"event_type"`
		Summary    string    `json:"summary"`
		EvidenceID string    `json:"evidence_id"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.ledger.RecordIncidentTimelineEvent(ctx, actor, r.PathValue("id"), app.RecordIncidentTimelineInput{EventType: req.EventType, Summary: req.Summary, EvidenceID: req.EvidenceID, OccurredAt: req.OccurredAt})
		return http.StatusCreated, event, err
	})
}

func (s *Server) createIncidentWebhookReceiver(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		PublicKey string `json:"public_key"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		receiver, err := s.ledger.CreateIncidentWebhookReceiver(ctx, actor, app.CreateIncidentWebhookReceiverInput{IncidentID: r.PathValue("id"), Name: req.Name, Provider: req.Provider, PublicKey: req.PublicKey})
		return http.StatusCreated, receiver, err
	})
}

func (s *Server) receiveIncidentWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	timestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Header.Get("X-Evydence-Webhook-Timestamp")))
	if err != nil {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	record, event, err := s.ledger.HandleIncidentWebhook(r.Context(), app.HandleIncidentWebhookInput{
		ReceiverID: r.PathValue("receiver_id"),
		EventID:    r.Header.Get("X-Evydence-Webhook-Event-ID"),
		Timestamp:  timestamp,
		Signature:  r.Header.Get("X-Evydence-Webhook-Signature"),
		Body:       body,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusCreated, map[string]any{"webhook_event": record, "timeline_event": event})
}

func (s *Server) createRemediationTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IncidentID string     `json:"incident_id"`
		ReleaseID  string     `json:"release_id"`
		Title      string     `json:"title"`
		Owner      string     `json:"owner"`
		DueAt      *time.Time `json:"due_at"`
		EvidenceID string     `json:"evidence_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		task, err := s.ledger.CreateRemediationTask(ctx, actor, app.CreateRemediationTaskInput{IncidentID: req.IncidentID, ReleaseID: req.ReleaseID, Title: req.Title, Owner: req.Owner, DueAt: req.DueAt, EvidenceID: req.EvidenceID})
		return http.StatusCreated, task, err
	})
}

func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.IncidentReport(r.Context(), actor, r.URL.Query().Get("incident_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadSecurityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Category   string          `json:"category"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.evidenceIngestion.UploadSecurityScan(ctx, actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Category: req.Category, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadAPISecurityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.evidenceIngestion.UploadAPISecurityScan(ctx, actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadManualSecurityDocument(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID    string          `json:"product_id"`
		ReleaseID    string          `json:"release_id"`
		DocumentType string          `json:"document_type"`
		Title        string          `json:"title"`
		Sensitivity  string          `json:"sensitivity"`
		MediaType    string          `json:"media_type"`
		Payload      json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		doc, err := s.evidenceIngestion.UploadManualSecurityDocument(ctx, actor, app.UploadManualSecurityDocumentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, DocumentType: req.DocumentType, Title: req.Title, Sensitivity: req.Sensitivity, Raw: req.Payload, MediaType: req.MediaType})
		return http.StatusCreated, doc, err
	})
}

func (s *Server) createWaiver(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType  string    `json:"scope_type"`
		ScopeID    string    `json:"scope_id"`
		ControlID  string    `json:"control_id"`
		PolicyID   string    `json:"policy_id"`
		Owner      string    `json:"owner"`
		Risk       string    `json:"risk"`
		Reason     string    `json:"reason"`
		ExpiresAt  time.Time `json:"expires_at"`
		Supersedes string    `json:"supersedes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		waiver, err := s.riskDecisions.CreateWaiver(ctx, actor, app.CreateWaiverInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, ControlID: req.ControlID, PolicyID: req.PolicyID, Owner: req.Owner, Risk: req.Risk, Reason: req.Reason, ExpiresAt: req.ExpiresAt, Supersedes: req.Supersedes})
		return http.StatusCreated, waiver, err
	})
}

func (s *Server) approveWaiver(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		waiver, err := s.riskDecisions.ApproveWaiver(ctx, actor, r.PathValue("id"))
		return http.StatusOK, waiver, err
	})
}

func (s *Server) createApproval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		Decision    string `json:"decision"`
		Reason      string `json:"reason"`
		EvidenceID  string `json:"evidence_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		approval, err := s.riskDecisions.CreateApprovalRecord(ctx, actor, app.CreateApprovalInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Decision: req.Decision, Reason: req.Reason, EvidenceID: req.EvidenceID})
		return http.StatusCreated, approval, err
	})
}

func (s *Server) createRedactionProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Preset         string   `json:"preset"`
		AllowedTypes   []string `json:"allowed_types"`
		ExcludedFields []string `json:"excluded_fields"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		profile, err := s.packages.CreateRedactionProfile(ctx, actor, app.CreateRedactionProfileInput{Name: req.Name, Description: req.Description, Preset: req.Preset, AllowedTypes: req.AllowedTypes, ExcludedFields: req.ExcludedFields})
		return http.StatusCreated, profile, err
	})
}

func (s *Server) createCustomerPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID          string    `json:"product_id"`
		ReleaseID          string    `json:"release_id"`
		RedactionProfileID string    `json:"redaction_profile_id"`
		Title              string    `json:"title"`
		ExpiresAt          time.Time `json:"expires_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		pkg, err := s.packages.CreateCustomerSecurityPackage(ctx, actor, app.CreateCustomerPackageInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, RedactionProfileID: req.RedactionProfileID, Title: req.Title, ExpiresAt: req.ExpiresAt})
		return http.StatusCreated, pkg, err
	})
}

func (s *Server) getCustomerPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	pkg, err := s.packages.AccessCustomerSecurityPackage(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, pkg)
}

func (s *Server) downloadCustomerPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	archive, err := s.ledger.ExportCustomerSecurityPackageArchive(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeArchive(w, archive)
}

func (s *Server) securityReviewPackageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.SecurityReviewPackageReport(r.Context(), actor, r.URL.Query().Get("package_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessHTMLPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.packages.CRAReadinessHTMLPackage(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		ReportType    string   `json:"report_type"`
		AllowedFields []string `json:"allowed_fields"`
		Template      string   `json:"template"`
	}
	s.createWithLimit(w, r, app.ReportTemplateRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		tpl, err := s.packages.CreateCustomReportTemplate(ctx, actor, app.CreateReportTemplateInput{Name: req.Name, Version: req.Version, ReportType: req.ReportType, AllowedFields: req.AllowedFields, Template: req.Template})
		return http.StatusCreated, tpl, err
	})
}

func (s *Server) renderReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		report, err := s.packages.RenderCustomReport(ctx, actor, app.RenderReportInput{TemplateID: r.PathValue("id"), SubjectType: req.SubjectType, SubjectID: req.SubjectID})
		return http.StatusCreated, report, err
	})
}

func (s *Server) exportEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		bundle, err := s.packages.ExportEvidenceBundle(ctx, actor, req.ReleaseID, req.EvidenceIDs)
		return http.StatusCreated, bundle, err
	})
}

func (s *Server) importEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req domain.EvidenceBundle
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.packages.ImportEvidenceBundle(ctx, actor, req)
		return http.StatusCreated, record, err
	})
}

func (s *Server) uploadSPDXSBOM(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == "application/spdx+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			sbom, err := s.evidenceIngestion.UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, sbom, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.evidenceIngestion.UploadSPDXSBOM(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) createSBOMDiff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseSBOMID   string `json:"base_sbom_id"`
		TargetSBOMID string `json:"target_sbom_id"`
		ReleaseID    string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.evidenceIngestion.CreateSBOMDiff(ctx, actor, app.CreateSBOMDiffInput{BaseSBOMID: req.BaseSBOMID, TargetSBOMID: req.TargetSBOMID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) createEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID        string              `json:"product_id"`
		ProjectID        string              `json:"project_id"`
		ReleaseID        string              `json:"release_id"`
		BuildID          string              `json:"build_id"`
		DeploymentID     string              `json:"deployment_id"`
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
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.evidenceIngestion.CreateEvidence(ctx, actor, app.CreateEvidenceInput{
			ProductID: req.ProductID, ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, BuildID: req.BuildID, DeploymentID: req.DeploymentID,
			Type: req.Type, Subtype: req.Subtype, Title: req.Title,
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
	pageRequest, err := s.parsePageRequest(r, actor, "evidence", "release_id", "type")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	query := r.URL.Query()
	page, err := s.evidenceIngestion.ListEvidencePage(r.Context(), actor, app.EvidencePageRequest{
		ReleaseID: query.Get("release_id"),
		Type:      query.Get("type"),
		Page: appquery.PageRequest{
			PageSize:  pageRequest.pageSize,
			Sort:      pageRequest.sort,
			Direction: pageRequest.direction,
		},
		After: pageRequest.after,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePage(s, w, r, actor, "evidence", pageRequest, page)
}

func (s *Server) searchEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	pageRequest, err := s.parsePageRequestWithLegacyLimit(r, actor, "evidence-search", true, "product_id", "project_id", "release_id", "build_id", "deployment_id", "type", "subtype", "source", "source_system", "collector_id", "verification_status", "subject_type", "subject_id", "tag", "created_after", "created_before")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	query := r.URL.Query()
	sourceSystem := query.Get("source")
	if sourceSystem != "" && query.Get("source_system") != "" {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	if sourceSystem == "" {
		sourceSystem = query.Get("source_system")
	}
	createdAfter, err := parseOptionalRFC3339(query.Get("created_after"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	createdBefore, err := parseOptionalRFC3339(query.Get("created_before"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	page, err := s.evidenceIngestion.SearchEvidencePage(r.Context(), actor, app.EvidenceSearchPageRequest{
		Filter: app.EvidenceSearchInput{
			ProductID:          query.Get("product_id"),
			ProjectID:          query.Get("project_id"),
			ReleaseID:          query.Get("release_id"),
			BuildID:            query.Get("build_id"),
			DeploymentID:       query.Get("deployment_id"),
			Type:               query.Get("type"),
			Subtype:            query.Get("subtype"),
			SourceSystem:       sourceSystem,
			CollectorID:        query.Get("collector_id"),
			VerificationStatus: query.Get("verification_status"),
			SubjectType:        query.Get("subject_type"),
			SubjectID:          query.Get("subject_id"),
			Tag:                query.Get("tag"),
			CreatedAfter:       createdAfter,
			CreatedBefore:      createdBefore,
		},
		Page: appquery.PageRequest{
			PageSize:  pageRequest.pageSize,
			Sort:      pageRequest.sort,
			Direction: pageRequest.direction,
		},
		After: pageRequest.after,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePage(s, w, r, actor, "evidence-search", pageRequest, page)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	item, err := s.evidenceIngestion.GetEvidence(r.Context(), actor, r.PathValue("id"))
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
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.evidenceIngestion.SupersedeEvidence(ctx, actor, r.PathValue("id"), req.ReplacementEvidenceID, req.Reason)
		return http.StatusCreated, item, err
	})
}

func (s *Server) linkEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.evidenceIngestion.LinkEvidence(ctx, actor, r.PathValue("id"), req.TargetType, req.TargetID)
		return http.StatusCreated, item, err
	})
}

func (s *Server) recordEvidenceLifecycleEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action        string         `json:"action"`
		Reason        string         `json:"reason"`
		Details       map[string]any `json:"details"`
		ReplacementID string         `json:"replacement_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.evidenceIngestion.RecordEvidenceLifecycleEvent(ctx, actor, r.PathValue("id"), app.RecordEvidenceLifecycleInput{
			Action: req.Action, Reason: req.Reason, Details: req.Details, ReplacementID: req.ReplacementID,
		})
		return http.StatusCreated, event, err
	})
}

func (s *Server) listEvidenceLifecycleEvents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	events, err := s.evidenceIngestion.ListEvidenceLifecycleEvents(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "evidence/"+r.PathValue("id")+"/lifecycle-events", nil, events, func(event domain.EvidenceLifecycleEvent) (string, time.Time) {
		return event.ID, event.CreatedAt
	})
}

func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == "application/vnd.cyclonedx+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			sbom, err := s.evidenceIngestion.UploadSBOMPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, sbom, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.evidenceIngestion.UploadSBOM(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) getSBOM(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	sbom, err := s.evidenceIngestion.GetSBOM(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sbom)
}

func (s *Server) listSBOMComponents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	components, err := s.evidenceIngestion.ListSBOMComponents(r.Context(), actor, app.ListSBOMComponentsInput{
		SBOMID:     query.Get("sbom_id"),
		ReleaseID:  query.Get("release_id"),
		ArtifactID: query.Get("artifact_id"),
		Query:      query.Get("query"),
		PURL:       query.Get("purl"),
		Limit:      500,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePaginatedWithLegacyLimit(s, w, r, actor, "sbom-components", []string{"sbom_id", "release_id", "artifact_id", "query", "purl"}, true, components, func(component domain.SBOMComponentRecord, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(component.ID, time.Time{}, sort)
	})
}

func (s *Server) uploadVEX(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == "application/vnd.openvex+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			vex, err := s.evidenceIngestion.UploadVEXPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, vex, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.evidenceIngestion.UploadVEX(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) previewVEXImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
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
	preview, err := s.evidenceIngestion.PreviewVEXImport(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, preview)
}

func (s *Server) getVEX(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	vex, err := s.evidenceIngestion.GetVEXDocument(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, vex)
}

func (s *Server) getVEXImportReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.evidenceIngestion.GetVEXImportReport(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadCycloneDXVEX(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.evidenceIngestion.UploadCycloneDXVEX(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) previewCycloneDXVEXImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
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
	preview, err := s.evidenceIngestion.PreviewCycloneDXVEXImport(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, preview)
}

func (s *Server) uploadVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, nil, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
		scan, err := s.evidenceIngestion.UploadVulnerabilityScanPayload(ctx, actor, source)
		return http.StatusCreated, scan, err
	})
}

func (s *Server) getVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	scan, err := s.evidenceIngestion.GetVulnerabilityScan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, scan)
}

func (s *Server) createVulnerabilityDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status          string              `json:"status"`
		Justification   string              `json:"justification"`
		ImpactStatement string              `json:"impact_statement"`
		ActionStatement string              `json:"action_statement"`
		CustomerVisible bool                `json:"customer_visible"`
		InternalNotes   string              `json:"internal_notes"`
		EvidenceIDs     []string            `json:"evidence_ids"`
		SupportingRefs  []domain.SubjectRef `json:"supporting_refs"`
		VEXDocumentID   string              `json:"vex_document_id"`
		ReviewedAt      *time.Time          `json:"reviewed_at"`
		ReviewDueAt     *time.Time          `json:"review_due_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		decision, err := s.riskDecisions.CreateVulnerabilityDecision(ctx, actor, r.PathValue("id"), app.CreateVulnerabilityDecisionInput{
			Status:          req.Status,
			Justification:   req.Justification,
			ImpactStatement: req.ImpactStatement,
			ActionStatement: req.ActionStatement,
			CustomerVisible: req.CustomerVisible,
			InternalNotes:   req.InternalNotes,
			EvidenceIDs:     req.EvidenceIDs,
			SupportingRefs:  req.SupportingRefs,
			VEXDocumentID:   req.VEXDocumentID,
			ReviewedAt:      req.ReviewedAt,
			ReviewDueAt:     req.ReviewDueAt,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, externalVulnerabilityDecision(decision), nil
	})
}

func (s *Server) listVulnerabilityDecisions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	var active *bool
	if value := strings.TrimSpace(query.Get("active")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		active = &parsed
	}
	decisions, err := s.riskDecisions.ListVulnerabilityDecisions(r.Context(), actor, app.ListVulnerabilityDecisionsInput{
		ProductID:     query.Get("product_id"),
		ReleaseID:     query.Get("release_id"),
		Vulnerability: query.Get("vulnerability"),
		Component:     query.Get("component"),
		Status:        query.Get("status"),
		Active:        active,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	responses := make([]vulnerabilityDecisionResponse, 0, len(decisions))
	for _, decision := range decisions {
		responses = append(responses, externalVulnerabilityDecision(decision))
	}
	writeCreatedAtPaginated(s, w, r, actor, "vulnerability-decisions", []string{"product_id", "release_id", "vulnerability", "component", "status", "active"}, responses, func(decision vulnerabilityDecisionResponse) (string, time.Time) {
		return decision.ID, decision.CreatedAt
	})
}

// vulnerabilityDecisionResponse is the external projection of an append-only
// decision. Tenant-internal notes remain in the ledger for authorized internal
// workflows but never cross the HTTP response boundary or idempotency replay.
type vulnerabilityDecisionResponse struct {
	ID                string              `json:"id"`
	TenantID          string              `json:"tenant_id"`
	FindingID         string              `json:"finding_id"`
	ScanID            string              `json:"scan_id"`
	ReleaseID         string              `json:"release_id,omitempty"`
	Vulnerability     string              `json:"vulnerability"`
	Component         string              `json:"component,omitempty"`
	SBOMID            string              `json:"sbom_id,omitempty"`
	SBOMComponentPURL string              `json:"sbom_component_purl,omitempty"`
	SBOMComponentName string              `json:"sbom_component_name,omitempty"`
	Status            string              `json:"status"`
	Justification     string              `json:"justification"`
	ImpactStatement   string              `json:"impact_statement,omitempty"`
	ActionStatement   string              `json:"action_statement,omitempty"`
	CustomerVisible   bool                `json:"customer_visible"`
	Source            string              `json:"source"`
	EvidenceID        string              `json:"evidence_id,omitempty"`
	EvidenceIDs       []string            `json:"evidence_ids,omitempty"`
	SupportingRefs    []domain.SubjectRef `json:"supporting_refs,omitempty"`
	VEXDocumentID     string              `json:"vex_document_id,omitempty"`
	Supersedes        string              `json:"supersedes,omitempty"`
	SupersededBy      string              `json:"superseded_by,omitempty"`
	ApprovedBy        string              `json:"approved_by,omitempty"`
	ReviewedAt        *time.Time          `json:"reviewed_at,omitempty"`
	ReviewDueAt       *time.Time          `json:"review_due_at,omitempty"`
	SchemaVersion     string              `json:"schema_version"`
	CreatedAt         time.Time           `json:"created_at"`
}

func externalVulnerabilityDecision(decision domain.VulnerabilityDecision) vulnerabilityDecisionResponse {
	return vulnerabilityDecisionResponse{
		ID:                decision.ID,
		TenantID:          decision.TenantID,
		FindingID:         decision.FindingID,
		ScanID:            decision.ScanID,
		ReleaseID:         decision.ReleaseID,
		Vulnerability:     decision.Vulnerability,
		Component:         decision.Component,
		SBOMID:            decision.SBOMID,
		SBOMComponentPURL: decision.SBOMComponentPURL,
		SBOMComponentName: decision.SBOMComponentName,
		Status:            decision.Status,
		Justification:     decision.Justification,
		ImpactStatement:   decision.ImpactStatement,
		ActionStatement:   decision.ActionStatement,
		CustomerVisible:   decision.CustomerVisible,
		Source:            decision.Source,
		EvidenceID:        decision.EvidenceID,
		EvidenceIDs:       decision.EvidenceIDs,
		SupportingRefs:    decision.SupportingRefs,
		VEXDocumentID:     decision.VEXDocumentID,
		Supersedes:        decision.Supersedes,
		SupersededBy:      decision.SupersededBy,
		ApprovedBy:        decision.ApprovedBy,
		ReviewedAt:        decision.ReviewedAt,
		ReviewDueAt:       decision.ReviewDueAt,
		SchemaVersion:     decision.SchemaVersion,
		CreatedAt:         decision.CreatedAt,
	}
}

func (s *Server) recordVulnerabilityWorkflow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.RecordVulnerabilityWorkflow(ctx, actor, app.RecordVulnerabilityWorkflowInput{FindingID: r.PathValue("id"), Action: req.Action, Reason: req.Reason})
		return http.StatusCreated, record, err
	})
}

func (s *Server) vulnerabilityPostureReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.VulnerabilityPostureReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) vulnerabilityDecisionSummaryReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.riskDecisions.VulnerabilityDecisionSummaryReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == "application/vnd.oai.openapi+json" {
		productID, err := requiredSingleHeader(r, "X-Evydence-Product-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		version, err := requiredSingleHeader(r, "X-Evydence-Version")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"media_type": requestMediaType(r), "product_id": productID, "release_id": releaseID, "version": version,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			contract, err := s.evidenceIngestion.UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, source)
			return http.StatusCreated, contract, err
		})
		return
	}
	var req struct {
		ProductID string          `json:"product_id"`
		ReleaseID string          `json:"release_id"`
		Version   string          `json:"version"`
		Spec      json.RawMessage `json:"spec"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		contract, err := s.evidenceIngestion.UploadOpenAPIContract(ctx, actor, req.ProductID, req.ReleaseID, req.Version, req.Spec)
		return http.StatusCreated, contract, err
	})
}

func (s *Server) getOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	contract, err := s.evidenceIngestion.GetOpenAPIContract(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, contract)
}

func (s *Server) createOpenAPIDiff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseContractID   string `json:"base_contract_id"`
		TargetContractID string `json:"target_contract_id"`
		ReleaseID        string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.evidenceIngestion.CreateContractDiff(ctx, actor, app.CreateContractDiffInput{BaseContractID: req.BaseContractID, TargetContractID: req.TargetContractID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.riskDecisions.EvaluateRelease(ctx, actor, req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) createCustomPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string              `json:"name"`
		Version     string              `json:"version"`
		Description string              `json:"description"`
		Rules       []domain.PolicyRule `json:"rules"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		policy, err := s.ledger.CreateCustomPolicy(ctx, actor, app.CreateCustomPolicyInput{Name: req.Name, Version: req.Version, Description: req.Description, Rules: req.Rules})
		return http.StatusCreated, policy, err
	})
}

func (s *Server) evaluateCustomPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.ledger.EvaluateCustomPolicy(ctx, actor, r.PathValue("id"), req.ReleaseID)
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
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		exception, err := s.riskDecisions.CreateException(ctx, actor, app.CreateExceptionInput{
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
	exceptions, err := s.riskDecisions.ListExceptions(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "exceptions", []string{"release_id"}, exceptions, func(exception domain.Exception) (string, time.Time) {
		return exception.ID, exception.CreatedAt
	})
}

func (s *Server) approveException(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		exception, err := s.riskDecisions.ApproveException(ctx, actor, r.PathValue("id"))
		return http.StatusOK, exception, err
	})
}

func (s *Server) releaseReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.packages.ReleaseReadinessReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) controlCoverageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.ControlCoverageReport(r.Context(), actor, app.ControlCoverageReportInput{
		FrameworkID: r.URL.Query().Get("framework_id"),
		ProductID:   r.URL.Query().Get("product_id"),
		ReleaseID:   r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CRAReadinessReport(r.Context(), actor, app.CRAReadinessReportInput{
		ProductID: r.URL.Query().Get("product_id"),
		ReleaseID: r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craVulnerabilityHandlingReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.CRAVulnerabilityHandlingReport(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) securityUpdateEvidenceReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.SecurityUpdateEvidenceReport(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
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
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		bundle, err := s.packages.CreateReleaseBundle(ctx, actor, req.ReleaseID)
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
	result, err := s.verification.VerifySubject(r.Context(), actor, "release_bundle", r.PathValue("id"))
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
	result, err := s.verification.VerifySubject(r.Context(), actor, "audit_chain", "")
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listAuditLog(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var since *time.Time
	if value := strings.TrimSpace(r.URL.Query().Get("since")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		since = &parsed
	}
	entries, err := s.ledger.ListAuditLog(r.Context(), actor, app.AuditLogFilter{
		SubjectType: r.URL.Query().Get("subject_type"),
		SubjectID:   r.URL.Query().Get("subject_id"),
		Since:       since,
		Limit:       500,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginatedWithLegacyLimit(s, w, r, actor, "audit-log", []string{"subject_type", "subject_id", "since"}, entries, func(entry domain.AuditChainEntry) (string, time.Time) {
		return entry.ID, entry.OccurredAt
	})
}

func (s *Server) createMerkleBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromSequence int64 `json:"from_sequence"`
		ToSequence   int64 `json:"to_sequence"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		batch, err := s.verification.CreateMerkleBatch(ctx, actor, app.CreateMerkleBatchInput{FromSequence: req.FromSequence, ToSequence: req.ToSequence})
		return http.StatusCreated, batch, err
	})
}

func (s *Server) verifyMerkleBatch(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.verification.VerifyMerkleBatch(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) createTransparencyCheckpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BatchID     string `json:"batch_id"`
		Provider    string `json:"provider"`
		ExternalURL string `json:"external_url"`
		ExternalID  string `json:"external_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		checkpoint, err := s.verification.CreateTransparencyCheckpoint(ctx, actor, app.CreateTransparencyCheckpointInput{BatchID: req.BatchID, Provider: req.Provider, ExternalURL: req.ExternalURL, ExternalID: req.ExternalID})
		return http.StatusCreated, checkpoint, err
	})
}

func (s *Server) createObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                    string `json:"name"`
		ObjectPrefix            string `json:"object_prefix"`
		ObjectKey               string `json:"object_key"`
		RequireLegalHold        bool   `json:"require_legal_hold"`
		Mode                    string `json:"mode"`
		RetentionDays           int    `json:"retention_days"`
		MaxVerificationAgeHours int    `json:"max_verification_age_hours"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		policy, err := s.verification.CreateObjectRetentionPolicy(ctx, actor, app.CreateObjectRetentionPolicyInput{Name: req.Name, ObjectPrefix: req.ObjectPrefix, ObjectKey: req.ObjectKey, RequireLegalHold: req.RequireLegalHold, Mode: req.Mode, RetentionDays: req.RetentionDays, MaxVerificationAgeHours: req.MaxVerificationAgeHours})
		return http.StatusCreated, policy, err
	})
}

func (s *Server) verifyObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		policy, err := s.verification.VerifyObjectRetentionPolicy(ctx, actor, r.PathValue("id"))
		return http.StatusOK, policy, err
	})
}

func (s *Server) signingCustodyReviewReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.verification.SigningCustodyReviewReport(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) generateBackupManifest(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		manifest, err := s.verification.GenerateBackupManifest(ctx, actor)
		return http.StatusCreated, manifest, err
	})
}

func (s *Server) verifyBackupManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.verification.VerifyBackupManifest(r.Context(), actor, r.PathValue("id"))
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
	keys, err := s.verification.ListSigningKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "signing-keys", nil, keys, func(key domain.SigningKey) (string, time.Time) {
		return key.ID, key.CreatedAt
	})
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if len(bytes.TrimSpace(body)) > 0 {
			if err := decodeJSON(body, &req); err != nil {
				return 0, nil, err
			}
		}
		key, err := s.verification.RotateSigningKey(ctx, actor, req.Reason)
		return http.StatusCreated, key, err
	})
}

func (s *Server) revokeSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason                   string `json:"reason"`
		Semantics                string `json:"semantics"`
		HistoricalValidityPolicy string `json:"historical_validity_policy"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if len(bytes.TrimSpace(body)) > 0 {
			if err := decodeJSON(body, &req); err != nil {
				return 0, nil, err
			}
		}
		key, err := s.verification.RevokeSigningKeyWithPolicy(ctx, actor, r.PathValue("id"), app.SigningKeyRevocationInput{
			Reason:                   req.Reason,
			Semantics:                req.Semantics,
			HistoricalValidityPolicy: req.HistoricalValidityPolicy,
		})
		return http.StatusOK, key, err
	})
}

func (s *Server) createSigningProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		KeyRef    string `json:"key_ref"`
		Encrypted bool   `json:"encrypted"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		provider, err := s.verification.CreateSigningProvider(ctx, actor, app.CreateSigningProviderInput{Name: req.Name, Type: req.Type, KeyRef: req.KeyRef, Encrypted: req.Encrypted})
		return http.StatusCreated, provider, err
	})
}

func (s *Server) createCommercialCollector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Provider      string   `json:"provider"`
		Version       string   `json:"version"`
		ManifestHash  string   `json:"manifest_hash"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		definition, err := s.ledger.CreateCommercialCollectorDefinition(ctx, actor, app.CreateCommercialCollectorInput{
			Name:          req.Name,
			Provider:      req.Provider,
			Version:       req.Version,
			ManifestHash:  req.ManifestHash,
			AllowedScopes: req.AllowedScopes,
		})
		return http.StatusCreated, definition, err
	})
}

func (s *Server) listCommercialCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	definitions, err := s.ledger.ListCommercialCollectorDefinitions(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "commercial-collectors", nil, definitions, func(definition domain.CommercialCollectorDefinition) (string, time.Time) {
		return definition.ID, definition.CreatedAt
	})
}

func (s *Server) verifySubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		result, err := s.verification.VerifySubject(ctx, actor, req.SubjectType, req.SubjectID)
		return http.StatusOK, result, err
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		key, secret, err := s.identityAccess.CreateAPIKey(ctx, actor, req.Name, req.Scopes, req.ExpiresAt)
		return http.StatusCreated, map[string]any{"api_key": key, "secret": secret}, err
	})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	keys, err := s.identityAccess.ListAPIKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "api-keys", nil, keys, func(key domain.APIKey) (string, time.Time) {
		return key.ID, key.CreatedAt
	})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error)) {
	s.createWithLimit(w, r, app.SmallJSONRequestLimit, run)
}

func (s *Server) createWithLimit(w http.ResponseWriter, r *http.Request, limit int64, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error)) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBodyLimit(r, limit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status, response, err := s.idempotency.WithBody(ctx, actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), body, func(commandCtx context.Context, scope commandScope) (int, any, error) {
		commandServer := *s
		scope.bind(&commandServer)
		return run(&commandServer, commandCtx, actor, body)
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
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if authHeader == "" {
		if cookie, err := r.Cookie(ssoSessionCookieName); err == nil {
			token = strings.TrimSpace(cookie.Value)
		}
	}
	actor, err := s.authn.Authenticate(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, identityapp.ErrUnauthorized):
			err = app.ErrUnauthorized
		case errors.Is(err, identityapp.ErrForbidden):
			err = app.ErrForbidden
		}
		writeProblem(w, r, err)
		return domain.Actor{}, false
	}
	if !s.allowExpensiveTenantRequest(actor, r) {
		writeProblem(w, r, app.ErrRateLimited)
		return domain.Actor{}, false
	}
	return actor, true
}

func readBody(r *http.Request) ([]byte, error) {
	return readBodyLimit(r, app.SmallJSONRequestLimit)
}

func readBodyLimit(r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil || limit <= 0 || r.ContentLength > limit {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "invalid_size"})
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "unreadable"})
	}
	if int64(len(body)) > limit {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "too_large"})
	}
	return body, nil
}

func decodeJSON(body []byte, out any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		trimmed = []byte(`{}`)
	}
	if err := jsonbounds.Validate(trimmed, jsonbounds.DefaultLimits()); err != nil {
		return app.NewValidationError()
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return jsonValidationError(err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return app.NewValidationError()
	}
	return nil
}

func jsonValidationError(err error) error {
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		return app.NewValidationError(app.FieldViolation{Field: jsonFieldPointer(typeError.Field), Code: "invalid_type"})
	}
	const unknownFieldPrefix = "json: unknown field "
	if raw := strings.TrimPrefix(err.Error(), unknownFieldPrefix); raw != err.Error() {
		if field, unquoteErr := strconv.Unquote(raw); unquoteErr == nil {
			return app.NewValidationError(app.FieldViolation{Field: jsonFieldPointer(field), Code: "unknown_field"})
		}
	}
	return app.NewValidationError()
}

func jsonFieldPointer(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	parts := strings.Split(field, ".")
	for index, part := range parts {
		parts[index] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(parts, "/")
}

func parseOptionalRFC3339(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, app.ErrValidation
	}
	return parsed, nil
}

func expectedRevisionFromIfMatch(r *http.Request) (int64, error) {
	if r == nil || len(r.Header.Values("If-Match")) != 1 {
		return 0, app.ErrValidation
	}
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, app.ErrValidation
	}
	value := raw[1 : len(raw)-1]
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value {
		return 0, app.ErrValidation
	}
	return revision, nil
}

func writeData(w http.ResponseWriter, status int, data any) {
	httpx.WriteJSON(w, status, map[string]any{"data": data, "meta": map[string]string{"api_version": "v1"}})
}

func writeArchive(w http.ResponseWriter, archive app.CustomerPackageArchive) {
	w.Header().Set("Content-Type", archive.MediaType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+archive.Filename+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(archive.Size, 10))
	w.Header().Set("X-Evydence-Archive-Hash", archive.Hash)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive.Bytes)
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	details := app.DescribeProblem(err)
	status := details.Status
	requestID := requestIDFromRequest(r)
	w.Header().Set(requestIDHeader, requestID)
	if details.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(details.RetryAfterSeconds))
	}
	problem := httpx.Problem{
		Type:   "https://evydence.local/problems/" + strings.ToLower(strings.ReplaceAll(string(details.Code), "_", "-")),
		Title:  http.StatusText(status),
		Detail: details.Detail,
		Ext: map[string]any{
			"code":        details.Code,
			"request_id":  requestID,
			"retryable":   details.Retryable,
			"retry_class": details.RetryClass,
		},
	}
	if details.RetryAfterSeconds > 0 {
		problem.Ext["retry_after_seconds"] = details.RetryAfterSeconds
	}
	if len(details.Violations) > 0 {
		problem.Ext["violations"] = details.Violations
	}
	if revision, ok := app.CurrentRevision(err); ok {
		problem.Ext["current_revision"] = revision
	}
	if r != nil {
		problem.Instance = r.URL.Path
	}
	httpx.WriteProblem(w, status, problem)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
		if !safeRequestID(requestID) {
			requestID = newRequestID()
		}
		r.Header.Set(requestIDHeader, requestID)
		w.Header().Set(requestIDHeader, requestID)
		next.ServeHTTP(w, r)
	})
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return newRequestID()
	}
	requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
	if safeRequestID(requestID) {
		return requestID
	}
	return newRequestID()
}

func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(buf[:])
}

func safeRequestID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
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
	successStatus := defaultSuccessStatus(id, method)
	operation := specs.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Tags:        []string{"evydence"},
		Responses: map[int]specs.Response{
			successStatus: {Description: summary + " response"},
			400:           {Description: "Bad request"},
			401:           {Description: "Unauthorized"},
			403:           {Description: "Forbidden"},
			404:           {Description: "Not found"},
			409:           {Description: "Conflict"},
			422:           {Description: "Verification failed"},
		},
	}
	if len(scopes) > 0 {
		operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
		operation.Scopes = scopes
	}
	if method == http.MethodPost {
		operation.Extensions = withStability(id, idempotent.OperationExtensions(true))
	} else {
		operation.Extensions = withStability(id, nil)
	}
	return withCriticalOperationDetails(operation)
}

func authenticatedOp(id, method, path, summary string) specs.Operation {
	operation := op(id, method, path, summary, nil)
	operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
	return operation
}

func readOnlyPostOp(id, method, path, summary string, scopes []string) specs.Operation {
	operation := op(id, method, path, summary, scopes)
	operation.Extensions = withStability(id, idempotent.OperationExtensions(false))
	return operation
}

func publicPostOp(id, method, path, summary string) specs.Operation {
	operation := op(id, method, path, summary, nil)
	operation.Security = nil
	operation.Scopes = nil
	operation.Extensions = withStability(id, nil)
	return operation
}

func withStability(operationID string, extensions map[string]any) map[string]any {
	result := make(map[string]any, len(extensions)+1)
	for name, value := range extensions {
		result[name] = value
	}
	result["x-evydence-stability"] = stabilityForOperation(operationID)
	return result
}

func stabilityForOperation(operationID string) string {
	switch operationID {
	case "createProduct", "listProducts", "getProduct",
		"createProject", "getProject",
		"createRelease", "getRelease", "startReleaseEvidenceFlow",
		"freezeRelease", "approveRelease",
		"registerArtifact", "getArtifact",
		"createBuild", "getBuild", "uploadBuildAttestation",
		"createEvidence", "getEvidence", "listEvidence", "linkEvidence",
		"uploadSBOM", "uploadSPDXSBOM", "getSBOM", "listSBOMComponents",
		"uploadVulnerabilityScan", "getVulnerabilityScan",
		"uploadVEX", "uploadCycloneDXVEX", "getVEX",
		"createVulnerabilityDecision", "listVulnerabilityDecisions",
		"createException", "approveException", "createApproval",
		"releaseReadinessReport", "releaseSecuritySummary",
		"createReleaseBundle", "getReleaseBundle", "getReleaseBundleManifest",
		"verifyReleaseBundle", "createCustomerPackage", "getCustomerPackage",
		"downloadCustomerPackage", "verify":
		return "core"
	case "health", "ready", "version", "openapi", "metrics",
		"createAPIKey", "listAPIKeys", "exchangeSSOCredential",
		"logoutSSOSession", "createCustomerPortalAccess",
		"accessCustomerPortalPackage", "downloadCustomerPortalPackage":
		return "supported"
	default:
		return "experimental"
	}
}

func defaultSuccessStatus(operationID, method string) int {
	if method == http.MethodGet {
		return http.StatusOK
	}
	if method != http.MethodPost {
		return http.StatusOK
	}
	switch operationID {
	case "deactivateUser",
		"logoutSSOSession",
		"revokeSSOSession",
		"refreshSSOProviderOIDCTrustMaterial",
		"updateSSOProviderTrustMaterial",
		"freezeRelease",
		"approveRelease",
		"promoteReleaseCandidate",
		"rejectReleaseCandidate",
		"verifyCosignSignature",
		"verifyBuildAttestationSignature",
		"previewVEXImport",
		"previewCycloneDXVEXImport",
		"approveWaiver",
		"accessCustomerPortalPackage",
		"downloadCustomerPortalPackage",
		"customerPortalPackageView",
		"downloadCustomerPortalPackageView",
		"revokeCustomerPortalAccess",
		"approveException",
		"verifyObjectRetentionPolicy",
		"verifyPublicTransparencyLogEntry",
		"fetchPublicTransparencyLogEntryProof",
		"revokeSigningKey",
		"verify":
		return http.StatusOK
	default:
		return http.StatusCreated
	}
}
