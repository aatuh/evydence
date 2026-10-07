package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestPDFHTTPLocalReplayRechecksCurrentGrant(t *testing.T) {
	base, secret := testServer(t)
	p := postRaw(t, base, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: dataField(t, p, "id"), Scopes: []string{"report:read"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`{"report_type":"release_readiness","product_id":%q,"title":"Readiness"}`, dataField(t, p, "id")))
	postRaw(t, s, secret, "/v1/reports/pdf", "pdf", body, 201)
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/reports/pdf", "pdf", body, 403)
}

type pdfHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *pdfHTTPFake) AuthorizeCreatePDFReportPackage(context.Context, identitydomain.Actor, packageapp.CreatePDFReportInput) error {
	f.guards++
	return f.guardErr
}
func (f *pdfHTTPFake) CreatePDFReportPackage(_ context.Context, a identitydomain.Actor, in packageapp.CreatePDFReportInput) (packagedomain.PDFReportPackage, error) {
	f.calls++
	return packagedomain.PDFReportPackage{ID: "pdf", TenantID: a.TenantID, ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title, PayloadHash: "sha256:hash", PayloadSize: 100, Limitations: []string{"packaging only"}, SchemaVersion: packagedomain.PDFReportPackageVersion}, f.runErr
}
func TestPDFHTTPFocusedInputAndPrivateErrorMapping(t *testing.T) {
	base, secret := testServer(t)
	f := &pdfHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PDFReportCommands: f}); err == nil {
		t.Fatal("PDF commands lack durable replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{PDFReportCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/reports/pdf"
	for i, bad := range []string{`null`, `[]`, `{}`, `{"report_type":"x","product_id":"p","title":null}`, `{"report_type":"x","product_id":"p","Title":"Title"}`, `{"report_type":"x","product_id":"p","title":"Title","title":"Title"}`, `{"report_type":"x","product_id":"p","title":"Title","unknown":true}`, `{"report_type":"x","product_id":"p","title":"Title\n2 0 obj"}`, `{"report_type":"x","product_id":"p","title":"` + string([]byte{255}) + `"}`, `{"report_type":"x","product_id":"` + strings.Repeat("p", 1025) + `","title":"Title"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid PDF input reached commands")
	}
	body := []byte(`{"report_type":"release_readiness","release_id":"release","title":"Readiness"}`)
	postRaw(t, s, "", path, "unauth", body, 401)
	out := postRaw(t, s, secret, path, "valid", body, 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"payload_hash"`) || strings.Contains(out, `"product_id"`) || strings.Contains(out, `"payload_ref"`) || strings.Contains(out, `"PayloadHash"`) {
		t.Fatal("PDF public response changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private PDF SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), body, ec.status)
			if strings.Contains(out, "private PDF SQL") || strings.Contains(out, `"payload_hash"`) || stage == "guard" && f.calls != before {
				t.Fatal("failed PDF leaked data or skipped guard", out)
			}
		}
	}
}
func TestPDFHTTPCookieMutationRequiresOriginBothProfiles(t *testing.T) {
	base, _ := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &pdfHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.PDFReportCommands = f
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/reports/pdf", strings.NewReader(`{"report_type":"x","product_id":"p","title":"Title"}`))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
		r.Header.Set("Idempotency-Key", "origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 || f.guards+f.calls != 0 {
			t.Fatal("PDF cookie mutation bypassed origin", w.Code)
		}
	}
}
