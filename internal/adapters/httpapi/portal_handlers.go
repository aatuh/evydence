package httpapi

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const maxPortalFormBody = 64 << 10

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
	setPortalNoStoreHeaders(w)
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
	setPortalNoStoreHeaders(w)
	writeArchive(w, archive)
}

func (s *Server) customerPortalPackageViewForm(w http.ResponseWriter, r *http.Request) {
	writePortalHTML(w, http.StatusOK, customerPortalPackageFormHTML(""))
}

func (s *Server) customerPortalPackageView(w http.ResponseWriter, r *http.Request) {
	req, err := readCustomerPortalForm(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	pkg, err := s.ledger.AccessCustomerPortalPackageWithAcceptance(r.Context(), req.Token, app.CustomerPortalAcceptanceInput{NDAAccepted: req.NDAAccepted, NDAAcceptedBy: req.NDAAcceptedBy})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePortalHTML(w, http.StatusOK, customerPortalPackageHTML(pkg))
}

func (s *Server) downloadCustomerPortalPackageView(w http.ResponseWriter, r *http.Request) {
	req, err := readCustomerPortalForm(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	archive, err := s.ledger.ExportCustomerPortalPackageArchiveWithAcceptance(r.Context(), req.Token, app.CustomerPortalAcceptanceInput{NDAAccepted: req.NDAAccepted, NDAAcceptedBy: req.NDAAcceptedBy})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setPortalNoStoreHeaders(w)
	writeArchive(w, archive)
}

type customerPortalFormRequest struct {
	Token         string
	NDAAccepted   bool
	NDAAcceptedBy string
}

func readCustomerPortalForm(r *http.Request) (customerPortalFormRequest, error) {
	if strings.TrimSpace(r.URL.RawQuery) != "" {
		return customerPortalFormRequest{}, app.ErrValidation
	}
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return customerPortalFormRequest{}, app.ErrValidation
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPortalFormBody+1))
	if err != nil || len(body) > maxPortalFormBody {
		return customerPortalFormRequest{}, app.ErrValidation
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return customerPortalFormRequest{}, app.ErrValidation
	}
	for key := range values {
		switch key {
		case "token", "nda_accepted", "nda_accepted_by":
			if len(values[key]) > 1 {
				return customerPortalFormRequest{}, app.ErrValidation
			}
		default:
			return customerPortalFormRequest{}, app.ErrValidation
		}
	}
	token := strings.TrimSpace(values.Get("token"))
	acceptedBy := strings.TrimSpace(values.Get("nda_accepted_by"))
	if token == "" || len(token) > 4096 || len(acceptedBy) > 256 {
		return customerPortalFormRequest{}, app.ErrValidation
	}
	accepted := false
	switch strings.ToLower(strings.TrimSpace(values.Get("nda_accepted"))) {
	case "", "false", "0", "off":
	case "true", "1", "on":
		accepted = true
	default:
		return customerPortalFormRequest{}, app.ErrValidation
	}
	return customerPortalFormRequest{Token: token, NDAAccepted: accepted, NDAAcceptedBy: acceptedBy}, nil
}

func writePortalHTML(w http.ResponseWriter, status int, body string) {
	setPortalNoStoreHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func setPortalNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func customerPortalPackageFormHTML(message string) string {
	var b strings.Builder
	writePortalHTMLHead(&b, "Evydence Package Review")
	b.WriteString("<main><h1>Evydence package review</h1>")
	if strings.TrimSpace(message) != "" {
		b.WriteString("<p class=\"notice\">")
		b.WriteString(escapeHTML(message))
		b.WriteString("</p>")
	}
	b.WriteString("<section><h2>Review package</h2><form method=\"post\" action=\"/v1/customer-portal/package/view\">")
	writePortalTokenFields(&b)
	b.WriteString("<button type=\"submit\">Review package</button></form></section>")
	b.WriteString("<section><h2>Download ZIP</h2><form method=\"post\" action=\"/v1/customer-portal/package/view/download\">")
	writePortalTokenFields(&b)
	b.WriteString("<button type=\"submit\">Download ZIP</button></form></section>")
	b.WriteString("<p class=\"notice\">Package review supports technical evidence review and compliance readiness only. It is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.</p>")
	b.WriteString("</main></body></html>")
	return b.String()
}

func writePortalTokenFields(b *strings.Builder) {
	b.WriteString("<label>Portal token<input name=\"token\" type=\"password\" autocomplete=\"off\" required></label>")
	b.WriteString("<label class=\"check\"><input name=\"nda_accepted\" type=\"checkbox\" value=\"true\"> NDA accepted if required</label>")
	b.WriteString("<label>NDA accepted by<input name=\"nda_accepted_by\" autocomplete=\"off\"></label>")
}

func customerPortalPackageHTML(pkg domain.CustomerSecurityPackage) string {
	var b strings.Builder
	writePortalHTMLHead(&b, "Evydence Package "+pkg.ID)
	b.WriteString("<main><h1>")
	b.WriteString(escapeHTML(pkg.Title))
	b.WriteString("</h1><p class=\"notice\">This page is generated from a scoped, redacted customer package. It omits raw tenant evidence payloads and internal notes.</p>")
	b.WriteString("<section><h2>Scope</h2><dl>")
	portalDefinition(&b, "package_id", pkg.ID)
	portalDefinition(&b, "product_id", pkg.ProductID)
	portalDefinition(&b, "release_id", pkg.ReleaseID)
	portalDefinition(&b, "state", pkg.State)
	portalDefinition(&b, "manifest_hash", pkg.ManifestHash)
	portalDefinition(&b, "expires_at", pkg.ExpiresAt.UTC().Format(time.RFC3339))
	if pkg.DistributionWatermark != "" {
		portalDefinition(&b, "distribution_watermark", pkg.DistributionWatermark)
	}
	b.WriteString("</dl></section>")
	for _, section := range []struct {
		Key   string
		Title string
	}{
		{"readiness_summary", "Readiness Summary"},
		{"vulnerability_decisions", "Vulnerability Decisions"},
		{"customer_decision_export", "Customer Decision Export"},
		{"customer_safe_gaps", "Customer-Safe Gaps"},
		{"artifact_digests", "Artifact Digests"},
		{"evidence_ids", "Included Evidence"},
		{"verification_material", "Verification Material"},
		{"reviewer_checklist", "Reviewer Checklist"},
		{"limitations", "Limitations"},
		{"non_claims", "Non-Claims"},
	} {
		portalManifestSection(&b, pkg.Manifest, section.Key, section.Title)
	}
	b.WriteString("<section><h2>Download ZIP</h2><form method=\"post\" action=\"/v1/customer-portal/package/view/download\">")
	writePortalTokenFields(&b)
	b.WriteString("<button type=\"submit\">Download ZIP</button></form></section>")
	b.WriteString("<p class=\"notice\">Review output supports technical evidence review and compliance readiness only. It is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.</p>")
	b.WriteString("</main></body></html>")
	return b.String()
}

func writePortalHTMLHead(b *strings.Builder, title string) {
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
	b.WriteString(escapeHTML(title))
	b.WriteString("</title><style>body{font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;margin:0;background:#f7f8fb;color:#152238}main{max-width:960px;margin:0 auto;padding:32px 20px}section{border:1px solid #d7dce5;background:#fff;margin:16px 0;padding:16px;border-radius:8px}h1{font-size:2rem;margin:0 0 12px}h2{font-size:1rem;margin:0 0 12px;color:#344054}label{display:block;margin:10px 0;font-weight:600}input{display:block;width:100%;max-width:560px;padding:10px;border:1px solid #b9c1d0;border-radius:6px}label.check{font-weight:500}label.check input{display:inline;width:auto;margin-right:8px}button{padding:10px 14px;border:0;border-radius:6px;background:#1d4ed8;color:#fff;font-weight:700}dl{display:grid;grid-template-columns:minmax(140px,220px)1fr;gap:8px 16px}dt{font-weight:700;color:#475467}dd{margin:0;word-break:break-word}ul{padding-left:22px}li{margin:6px 0}.notice{color:#475467}.key{font-weight:700;color:#475467}.empty{color:#667085}</style></head><body>")
}

func portalDefinition(b *strings.Builder, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	b.WriteString("<dt>")
	b.WriteString(escapeHTML(key))
	b.WriteString("</dt><dd>")
	b.WriteString(escapeHTML(value))
	b.WriteString("</dd>")
}

func portalManifestSection(b *strings.Builder, manifest map[string]any, key, title string) {
	value, ok := manifest[key]
	if !ok || portalValueEmpty(value) {
		return
	}
	b.WriteString("<section><h2>")
	b.WriteString(escapeHTML(title))
	b.WriteString("</h2>")
	portalHTMLValue(b, value, 0)
	b.WriteString("</section>")
}

func portalHTMLValue(b *strings.Builder, value any, depth int) {
	if depth > 5 {
		b.WriteString("<span class=\"empty\">nested content omitted</span>")
		return
	}
	switch typed := value.(type) {
	case nil:
		b.WriteString("<span class=\"empty\">not recorded</span>")
	case string:
		b.WriteString(escapeHTML(typed))
	case bool:
		if typed {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case float64, float32, int, int64, int32, uint, uint64, uint32:
		b.WriteString(escapeHTML(toString(typed)))
	case []any:
		if len(typed) == 0 {
			b.WriteString("<span class=\"empty\">none</span>")
			return
		}
		b.WriteString("<ul>")
		for i, item := range typed {
			if i >= 100 {
				b.WriteString("<li>additional entries omitted</li>")
				break
			}
			b.WriteString("<li>")
			portalHTMLValue(b, item, depth+1)
			b.WriteString("</li>")
		}
		b.WriteString("</ul>")
	case []string:
		if len(typed) == 0 {
			b.WriteString("<span class=\"empty\">none</span>")
			return
		}
		b.WriteString("<ul>")
		for i, item := range typed {
			if i >= 100 {
				b.WriteString("<li>additional entries omitted</li>")
				break
			}
			b.WriteString("<li>")
			b.WriteString(escapeHTML(item))
			b.WriteString("</li>")
		}
		b.WriteString("</ul>")
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if portalSensitiveManifestKey(key) {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			b.WriteString("<span class=\"empty\">none</span>")
			return
		}
		b.WriteString("<dl>")
		for _, key := range keys {
			b.WriteString("<dt>")
			b.WriteString(escapeHTML(key))
			b.WriteString("</dt><dd>")
			portalHTMLValue(b, typed[key], depth+1)
			b.WriteString("</dd>")
		}
		b.WriteString("</dl>")
	case map[string]string:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if portalSensitiveManifestKey(key) {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteString("<dl>")
		for _, key := range keys {
			portalDefinition(b, key, typed[key])
		}
		b.WriteString("</dl>")
	default:
		b.WriteString(escapeHTML(toString(typed)))
	}
}

func portalValueEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []any:
		return len(typed) == 0
	case []string:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	case map[string]string:
		return len(typed) == 0
	default:
		return false
	}
}

func portalSensitiveManifestKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "payload_ref", "payload_refs", "object_key", "object_keys", "object_url", "object_urls", "raw_payload", "raw_payload_bytes", "private_key", "private_keys", "token", "tokens", "token_hash", "token_hashes", "api_key", "api_keys", "secret", "secrets", "internal_notes":
		return true
	default:
		return false
	}
}

func toString(value any) string {
	return fmt.Sprint(value)
}

func escapeHTML(value string) string {
	return html.EscapeString(value)
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
