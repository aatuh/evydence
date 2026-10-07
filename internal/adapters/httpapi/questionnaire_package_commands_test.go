package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestQuestionnairePackageHTTPRequestSchemaBoundsAllCoordinates(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["CreateQuestionnairePackageRequest"]
	if len(schema.Required) != 1 || schema.Required[0] != "template_id" || schema.Properties["template_id"]["minLength"] != float64(1) {
		t.Fatal("required template contract changed")
	}
	for _, id := range []string{"template_id", "package_id", "product_id", "release_id"} {
		if schema.Properties[id]["type"] != "string" || schema.Properties[id]["maxLength"] != float64(1024) {
			t.Fatal("coordinate bounds missing", id)
		}
	}
}

type questionnairePackageHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *questionnairePackageHTTPFake) AuthorizeCreateQuestionnairePackage(context.Context, identitydomain.Actor, packageapp.CreateQuestionnairePackageInput) error {
	f.guards++
	return f.guardErr
}
func (f *questionnairePackageHTTPFake) CreateQuestionnairePackage(_ context.Context, a identitydomain.Actor, in packageapp.CreateQuestionnairePackageInput) (packagedomain.QuestionnairePackage, error) {
	f.calls++
	return packagedomain.QuestionnairePackage{ID: "generated", TenantID: a.TenantID, TemplateID: in.TemplateID, PackageID: in.PackageID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, ManifestHash: "sha256:hash", SchemaVersion: packagedomain.QuestionnairePackageVersion}, f.runErr
}
func TestQuestionnairePackageHTTPFocusedStrictJSONAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &questionnairePackageHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{QuestionnairePackageCommands: f}); err == nil {
		t.Fatal("commands lack durable executor")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{QuestionnairePackageCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/questionnaire-packages"
	const body = `{"template_id":"template","package_id":"package"}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"unknown":true}`, `{"template_id":null}`, `{"template_id":"template","package_id":null}`, `{"template_id":"template","product_id":null}`, `{"template_id":"template","release_id":null}`, `{"template_id":"a","template_id":"b"}`, `{"template_id":"a","TEMPLATE_ID":"b"}`, `{"template_id":"a\u0000"}`, `{"template_id":"` + string([]byte{0xff}) + `"}`, `{"template_id":" "}`, `{"template_id":"template","package_id":"` + strings.Repeat("x", 1025) + `"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid input reaches command")
	}
	postRaw(t, s, "", path, "anonymous", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"package_id":"package"`) || strings.Contains(out, `"product_id"`) || strings.Contains(out, `"ManifestHash"`) {
		t.Fatal("output shape differs", out)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private package SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = tc.err
			} else {
				f.runErr = tc.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), tc.status)
			if strings.Contains(out, "private package SQL") || strings.Contains(out, `"generated"`) || stage == "guard" && f.calls != before {
				t.Fatal("unsafe error/guard", out)
			}
		}
	}
}
func TestQuestionnairePackageHTTPOriginBothProfiles(t *testing.T) {
	base, secret := governanceTestServer(t)
	tpl := postRaw(t, base, secret, "/v1/questionnaire-templates", "template", []byte(`{"name":"Template","version":"1","questions":[{"id":"q","prompt":"Review?"}]}`), 201)
	body := fmt.Sprintf(`{"template_id":%q}`, dataField(t, tpl, "id"))
	for _, focused := range []bool{false, true} {
		opts := ServerOptions{}
		if focused {
			opts.QuestionnairePackageCommands = &questionnairePackageHTTPFake{}
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://example.com", false, 403}, {"https://example.com", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://example.com/v1/questionnaire-packages", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unsafe cookie mutation", focused, w.Code)
			}
		}
	}
}
func TestQuestionnairePackageHTTPLocalReplayCannotRetainPrivateAnswers(t *testing.T) {
	base, secret := governanceTestServer(t)
	product := postRaw(t, base, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	tpl := postRaw(t, base, secret, "/v1/questionnaire-templates", "template", []byte(`{"name":"Template","version":"1","questions":[{"id":"q","prompt":"Review?"}]}`), 201)
	postRaw(t, base, secret, "/v1/questionnaire-answer-library", "answer", []byte(`{"question_id":"q","answer":"private-global-answer"}`), 201)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"*"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`{"template_id":%q,"product_id":%q}`, dataField(t, tpl, "id"), dataField(t, product, "id")))
	if out := postRaw(t, s, secret, "/v1/questionnaire-packages", "saved", body, 201); !strings.Contains(out, "private-global-answer") {
		t.Fatal("authorized answer omitted")
	}
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: dataField(t, product, "id"), Scopes: []string{"*"}}}
	postRaw(t, s, secret, "/v1/questionnaire-packages", "saved", body, 409)
	if out := postRaw(t, s, secret, "/v1/questionnaire-packages", "new", body, 201); strings.Contains(out, "private-global-answer") {
		t.Fatal("scoped generation leaked global answer")
	}
}
