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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type draftHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func TestDraftHTTPLocalReplayCannotRetainPrivateAnswersAfterDowngrade(t *testing.T) {
	base, secret := testServer(t)
	product := postRaw(t, base, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	tpl := postRaw(t, base, secret, "/v1/questionnaire-templates", "template", []byte(`{"name":"Template","version":"1","questions":[{"id":"q","prompt":"Review?"}]}`), 201)
	postRaw(t, base, secret, "/v1/questionnaire-answer-library", "answer", []byte(`{"question_id":"q","answer":"private-global-answer"}`), 201)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID = ""
	a.UserID = "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"*"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`{"template_id":%q,"product_id":%q}`, dataField(t, tpl, "id"), dataField(t, product, "id")))
	first := postRaw(t, s, secret, "/v1/questionnaire-drafts", "saved", body, 201)
	if !strings.Contains(first, "private-global-answer") {
		t.Fatal("missing global draft answer")
	}
	auth.actor.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "product", ResourceID: dataField(t, product, "id"), Scopes: []string{"*"}}
	postRaw(t, s, secret, "/v1/questionnaire-drafts", "saved", body, 409)
	if scoped := postRaw(t, s, secret, "/v1/questionnaire-drafts", "scoped", body, 201); strings.Contains(scoped, "private-global-answer") {
		t.Fatal("local scoped draft leaked global answer")
	}
}

func TestDraftReplayFingerprintCanonicalizesGrantOrdering(t *testing.T) {
	a := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:read", "report:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"package:read", "report:read"}}, {ResourceType: "release", ResourceID: "release", Scopes: []string{"package:read"}}}}
	body := []byte(`{"template_id":"template"}`)
	one, err := questionnaireDraftReplayFingerprint(a, body)
	if err != nil {
		t.Fatal(err)
	}
	a.Scopes = []string{"report:read", "package:read", "package:read"}
	a.ResourceGrants = []domain.ResourceGrant{a.ResourceGrants[1], a.ResourceGrants[0], a.ResourceGrants[0]}
	a.ResourceGrants[1].Scopes = []string{"report:read", "package:read"}
	two, err := questionnaireDraftReplayFingerprint(a, body)
	if err != nil || string(one) != string(two) {
		t.Fatal("permission ordering changes replay identity", err)
	}
	a.ResourceGrants = nil
	three, err := questionnaireDraftReplayFingerprint(a, body)
	if err != nil || string(one) == string(three) {
		t.Fatal("permissions omitted from replay identity", err)
	}
}

func (f *draftHTTPFake) AuthorizeCreateQuestionnaireDraft(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireDraftInput) error {
	f.guards++
	return f.guardErr
}
func (f *draftHTTPFake) CreateQuestionnaireDraft(_ context.Context, a identitydomain.Actor, in packageapp.CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error) {
	f.calls++
	return packagedomain.QuestionnaireDraft{ID: "draft", TenantID: a.TenantID, TemplateID: in.TemplateID, ManifestHash: "sha256:hash", SchemaVersion: packagedomain.QuestionnaireDraftVersion}, f.runErr
}
func TestDraftHTTPFocusedCommandsStrictJSONAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &draftHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{QuestionnaireDraftCommands: f}); err == nil {
		t.Fatal("draft commands lack atomic replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{QuestionnaireDraftCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/questionnaire-drafts"
	const body = `{"template_id":"template"}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"unknown":true}`, `{"template_id":null}`, `{"template_id":"template","product_id":null}`, `{"template_id":"template","release_id":null}`, `{"template_id":"a","template_id":"b"}`, `{"template_id":"` + string([]byte{0xff}) + `"}`, `{"template_id":"a\u0000"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("invalid draft input reached command")
	}
	postRaw(t, s, "", path, "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || !strings.Contains(out, `"manifest_hash"`) || strings.Contains(out, `"ManifestHash"`) || strings.Contains(out, `"product_id"`) {
		t.Fatal("draft projection/optional fields differ", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private draft SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private draft SQL") || strings.Contains(out, `"draft"`) || stage == "guard" && f.calls != before {
				t.Fatal("draft error leaks/bypasses guard", out)
			}
		}
	}
}
func TestDraftHTTPCookieWritesRequireSameHTTPSOrigin(t *testing.T) {
	base, secret := testServer(t)
	f := &draftHTTPFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{QuestionnaireDraftCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		origin string
		bearer bool
		status int
	}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://example.com", false, 403}, {"https://example.com", false, 201}, {"https://attacker.example", true, 201}} {
		r := httptest.NewRequest("POST", "https://example.com/v1/questionnaire-drafts", strings.NewReader(`{"template_id":"template"}`))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		r.Header.Set("Origin", v.origin)
		r.Header.Set("Idempotency-Key", "origin")
		if v.bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		before := f.calls + f.guards
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != v.status || w.Header().Get("Set-Cookie") != "" || v.status == 403 && before != f.calls+f.guards {
			t.Fatal("unsafe cookie draft", w.Code)
		}
	}
}

func TestDraftHTTPRequestSchemaDeclaresBoundedOptionalCoordinates(t *testing.T) {
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
	schema := doc.Components.Schemas["CreateQuestionnaireDraftRequest"]
	if len(schema.Required) != 1 || schema.Required[0] != "template_id" {
		t.Fatal("draft coordinates must be optional", schema.Required)
	}
	for _, key := range []string{"template_id", "product_id", "release_id"} {
		p := schema.Properties[key]
		if p["type"] != "string" || p["maxLength"] != float64(packageapp.MaxQuestionnaireDraftIDBytes) {
			t.Fatal("draft identifier bounds missing", key, p)
		}
	}
	if schema.Properties["template_id"]["minLength"] != float64(1) {
		t.Fatal("blank template schema")
	}
}
