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

type answerLibraryHTTPFake struct {
	calls, guards    int
	guardErr, runErr error
}

func (f *answerLibraryHTTPFake) AuthorizeCreateAnswerLibraryEntry(context.Context, identitydomain.Actor, packageapp.CreateAnswerLibraryEntryInput) error {
	f.guards++
	return f.guardErr
}
func (f *answerLibraryHTTPFake) CreateAnswerLibraryEntry(_ context.Context, a identitydomain.Actor, in packageapp.CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error) {
	f.calls++
	return packagedomain.QuestionnaireAnswerLibraryEntry{ID: "answer", TenantID: a.TenantID, QuestionID: in.QuestionID, Answer: in.Answer, EvidenceIDs: in.EvidenceIDs, Limitations: in.Limitations, SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}, f.runErr
}
func TestAnswerLibraryHTTPStrictJSONFocusedProjectionAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &answerLibraryHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{AnswerLibraryCommands: f}); err == nil {
		t.Fatal("focused answers lack durable replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{AnswerLibraryCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/questionnaire-answer-library"
	const body = `{"question_id":"q","answer":" Draft "}`
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"question_id":"q","answer":null}`, `{"question_id":"q","answer":"Draft","control_id":null}`, `{"question_id":"q","answer":"Draft","evidence_ids":null}`, `{"question_id":"q","answer":"Draft","evidence_ids":[null]}`, `{"question_id":"q","answer":"Draft","limitations":[null]}`, `{"question_id":"q","answer":"Draft","unknown":true}`, `{"question_id":"q","answer":"Draft","ANSWER":"other"}`, `{"question_id":"q","answer":"Draft","CONTROL_ID":null}`, `{"question_id":"q","answer":"Draft","answer":"other"}`, `{"question_id":"q","answer":"Draft\u0000"}`, `{"question_id":"q","answer":"` + string([]byte{0xff}) + `"}`, `{"question_id":"q","answer":"Draft","evidence_ids":[" "]}`, `{"question_id":"q","answer":" "}`, `{"answer":"Draft"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	oversized := postRaw(t, s, secret, path, "body-limit", []byte(`{"question_id":"q","answer":"`+strings.Repeat("a", 64<<10)+`"}`), http.StatusBadRequest)
	if !strings.Contains(oversized, `"field":"/body"`) || !strings.Contains(oversized, `"code":"invalid_size"`) {
		t.Fatal("complete body limit lost the existing validation contract", oversized)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("malformed input reached commands")
	}
	postRaw(t, s, "", path, "anonymous", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || !strings.Contains(out, `"answer":"Draft"`) || strings.Contains(out, `"Answer"`) || strings.Contains(out, `"product_id"`) || strings.Contains(out, `"evidence_ids"`) {
		t.Fatal("focused shape differs", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private answer SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private answer SQL") || strings.Contains(out, `"answer":"Draft"`) || stage == "guard" && f.calls != before {
				t.Fatal("unsafe error/guard", out)
			}
		}
	}
}
func TestAnswerLibraryHTTPLocalReplayRechecksCurrentHumanGrants(t *testing.T) {
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
	const body = `{"question_id":"q","answer":"Draft"}`
	first := postRaw(t, s, secret, "/v1/questionnaire-answer-library", "replay", []byte(body), 201)
	if second := postRaw(t, s, secret, "/v1/questionnaire-answer-library", "replay", []byte(body), 201); first != second {
		t.Fatal("same-key replay differs")
	}
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "p", Scopes: []string{"*"}}}
	postRaw(t, s, secret, "/v1/questionnaire-answer-library", "replay", []byte(body), 403)
}
func TestAnswerLibraryHTTPCookieOriginBothProfiles(t *testing.T) {
	base, secret := testServer(t)
	for _, focused := range []bool{false, true} {
		opts := ServerOptions{}
		if focused {
			opts.AnswerLibraryCommands = &answerLibraryHTTPFake{}
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
			r := httptest.NewRequest("POST", "https://example.com/v1/questionnaire-answer-library", strings.NewReader(`{"question_id":"q","answer":"Draft"}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", v.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
			if v.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != v.status || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unsafe cookie mutation", focused, w.Code, w.Body.String())
			}
		}
	}
}
func TestAnswerLibraryOpenAPIBoundsOnlyNewRequests(t *testing.T) {
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
	in := doc.Components.Schemas["CreateQuestionnaireAnswerLibraryEntryRequest"].Properties
	if in["answer"]["maxLength"] != float64(65536) || in["question_id"]["maxLength"] != float64(1024) || in["evidence_ids"]["maxItems"] != float64(4096) || in["limitations"]["maxItems"] != float64(128) {
		t.Fatal("creation bounds missing", in)
	}
	if doc.Components.Schemas["QuestionnaireAnswerLibraryEntry"].Properties["answer"]["maxLength"] != nil {
		t.Fatal("historical answer responses restricted")
	}
}
