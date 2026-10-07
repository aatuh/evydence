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
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type qTemplateHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *qTemplateHTTPFake) AuthorizeCreateQuestionnaireTemplate(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireTemplateInput) error {
	f.guards++
	return f.guardErr
}
func (f *qTemplateHTTPFake) CreateQuestionnaireTemplate(_ context.Context, a identitydomain.Actor, in packageapp.CreateQuestionnaireTemplateInput) (packagedomain.QuestionnaireTemplate, error) {
	f.calls++
	return packagedomain.QuestionnaireTemplate{ID: "template", TenantID: a.TenantID, Name: in.Name, Version: in.Version, Questions: in.Questions, SchemaVersion: packagedomain.QuestionnaireTemplateVersion, CreatedAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}, f.runErr
}
func TestQTemplateHTTPStrictNestedJSONAndFocusedProjection(t *testing.T) {
	base, secret := testServer(t)
	f := &qTemplateHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{QuestionnaireTemplateCommands: f}); err == nil {
		t.Fatal("template commands lack atomic replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{QuestionnaireTemplateCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/questionnaire-templates"
	const body = `{"name":" Customer ","version":"1","questions":[{"id":"q","prompt":"Review?"}]}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"name":null}`, `{"name":"A","version":"1","questions":null}`, `{"name":"A","version":"1","questions":[null]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","control_id":null}]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","allowed_fields":null}]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","allowed_fields":[null]}]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","unknown":true}]}`, `{"name":"A","version":"1","questions":[{"id":"q","id":"b","prompt":"P"}]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P"},{"id":" q ","prompt":"P"}]}`, `{"name":"` + string([]byte{0xff}) + `","version":"1","questions":[{"id":"q","prompt":"P"}]}`, `{"name":"A","version":"1","questions":[{"id":"q","prompt":"P\u0000"}]}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("malformed template reached commands")
	}
	postRaw(t, s, secret, path, "case-null", []byte(`{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","CONTROL_ID":null}]}`), 400)
	postRaw(t, s, secret, path, "case-duplicate", []byte(`{"name":"A","version":"1","questions":[{"id":"q","prompt":"P","ID":"different"}]}`), 400)
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || !strings.Contains(out, `"name":"Customer"`) || strings.Contains(out, `"allowed_fields"`) || strings.Contains(out, `"Name"`) {
		t.Fatal("template public projection differs", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private template SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private template SQL") || strings.Contains(out, `"template"`) || stage == "guard" && f.calls != before {
				t.Fatal("error output/guard unsafe", out)
			}
		}
	}
}
func TestQTemplateHTTPCookieMutationGuardBothProfiles(t *testing.T) {
	base, secret := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &qTemplateHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.QuestionnaireTemplateCommands = f
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://example.com", false, 403}, {"https://example.com", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://example.com/v1/questionnaire-templates", strings.NewReader(`{"name":"T","version":"1","questions":[{"id":"q","prompt":"P"}]}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", v.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
			if v.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			before := f.calls + f.guards
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != v.status || w.Header().Get("Set-Cookie") != "" || v.status == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe template cookie write", focused, w.Code, w.Body.String())
			}
		}
	}
}

func TestQTemplateOpenAPIBoundsOnlyCreationNotHistoricalResponses(t *testing.T) {
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
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid contract")
	}
	in := doc.Components.Schemas["CreateQuestionnaireTemplateRequest"].Properties
	if in["name"]["maxLength"] != float64(1024) || in["version"]["maxLength"] != float64(1024) || in["questions"]["minItems"] != float64(1) || in["questions"]["maxItems"] != float64(512) || in["questions"]["items"].(map[string]any)["$ref"] != "#/components/schemas/CreateQuestionnaireQuestion" {
		t.Fatal("template request bounds missing", in)
	}
	q := doc.Components.Schemas["CreateQuestionnaireQuestion"].Properties
	if q["prompt"]["maxLength"] != float64(65536) || q["id"]["maxLength"] != float64(1024) || q["allowed_fields"]["maxItems"] != float64(128) {
		t.Fatal("question bounds missing", q)
	}
	if doc.Components.Schemas["QuestionnaireQuestion"].Properties["prompt"]["maxLength"] != nil {
		t.Fatal("historical responses were restricted")
	}
}

func TestQTemplateHTTPLocalReplayRechecksTenantWideAuthority(t *testing.T) {
	base, secret := testServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"*"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"name":"Customer","version":"1","questions":[{"id":"q","prompt":"Review?"}]}`
	first := postRaw(t, s, secret, "/v1/questionnaire-templates", "replay", []byte(body), 201)
	if second := postRaw(t, s, secret, "/v1/questionnaire-templates", "replay", []byte(body), 201); first != second {
		t.Fatal("local replay differs")
	}
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "p", Scopes: []string{"*"}}}
	postRaw(t, s, secret, "/v1/questionnaire-templates", "replay", []byte(body), 403)
}
