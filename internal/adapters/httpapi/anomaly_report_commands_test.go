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
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestAnomalyHTTPLocalReplayRechecksCurrentGrant(t *testing.T) {
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
	body := []byte(fmt.Sprintf(`{"subject_type":"product","subject_id":%q}`, dataField(t, p, "id")))
	postRaw(t, s, secret, "/v1/reports/anomaly", "anomaly", body, 201)
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/reports/anomaly", "anomaly", body, 403)
}

type anomalyHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *anomalyHTTPFake) AuthorizeGenerateAnomalyReport(context.Context, identitydomain.Actor, experimentalapp.AnomalyReportInput) error {
	f.guards++
	return f.guardErr
}
func (f *anomalyHTTPFake) GenerateAnomalyReport(_ context.Context, a identitydomain.Actor, in experimentalapp.AnomalyReportInput) (experimentaldomain.AnomalyReport, error) {
	f.calls++
	return experimentaldomain.AnomalyReport{ID: "anomaly", TenantID: a.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Result: "clear", Assumptions: []string{"recorded facts"}, Limitations: []string{"evidence anomalies only"}, SchemaVersion: experimentaldomain.AnomalyReportVersion}, f.runErr
}
func TestAnomalyHTTPFocusedValidationAndPrivateFailures(t *testing.T) {
	base, secret := testServer(t)
	f := &anomalyHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{AnomalyReportCommands: f}); err == nil {
		t.Fatal("focused anomaly bypassed durable replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{AnomalyReportCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for i, bad := range []string{`null`, `[]`, `{}`, `{"subject_type":"release","subject_id":null}`, `{"Subject_type":"release","subject_id":"r"}`, `{"subject_type":"release","subject_id":"r","subject_id":"r"}`, `{"subject_type":"release","subject_id":"r","unknown":true}`, `{"subject_type":"unknown","subject_id":"r"}`, `{"subject_type":"release","subject_id":"r"} {}`, `{"subject_type":"release","subject_id":"r\u0000"}`, `{"subject_type":"release","subject_id":"` + string([]byte{255}) + `"}`, `{"subject_type":"release","subject_id":"` + strings.Repeat("r", 1025) + `"}`} {
		postRaw(t, s, secret, "/v1/reports/anomaly", fmt.Sprint(i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid anomaly JSON reached command ports")
	}
	body := []byte(`{"subject_type":"release","subject_id":"release"}`)
	postRaw(t, s, "", "/v1/reports/anomaly", "unauth", body, 401)
	out := postRaw(t, s, secret, "/v1/reports/anomaly", "valid", body, 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"result":"clear"`) || strings.Contains(out, `"Signals"`) || strings.Contains(out, `"signals"`) {
		t.Fatal("clear anomaly response changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{experimentalapp.ErrValidation, 400}, {experimentalapp.ErrNotFound, 404}, {experimentalapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private anomaly SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/reports/anomaly", fmt.Sprintf("%s-%d", phase, i), body, ec.status)
			if strings.Contains(out, "private anomaly SQL") || strings.Contains(out, `"result":"clear"`) || phase == "guard" && f.calls != before {
				t.Fatal("failed anomaly leaked a report or bypassed guard", out)
			}
		}
	}
}
func TestAnomalyHTTPCookieOriginAndBearerPrecedenceBothProfiles(t *testing.T) {
	base, secret := testServer(t)
	p := postRaw(t, base, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	body := fmt.Sprintf(`{"subject_type":"product","subject_id":%q}`, dataField(t, p, "id"))
	for _, focused := range []bool{false, true} {
		f := &anomalyHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.AnomalyReportCommands = f
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example.test/v1/reports/anomaly", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
			r.Header.Set("Idempotency-Key", fmt.Sprintf("origin-%t-%t", focused, bearer))
			r.Header.Set("Content-Type", "application/json")
			want := 403
			if bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
				want = 201
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("anomaly cookie Origin or bearer precedence changed", focused, bearer, w.Code, w.Body.String())
			}
		}
	}
}

func TestAnomalyHTTPLocalRejectsAmbiguousJSON(t *testing.T) {
	s, secret := testServer(t)
	p := postRaw(t, s, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	id := dataField(t, p, "id")
	for i, body := range []string{
		fmt.Sprintf(`{"subject_type":"product","subject_id":%q,"subject_id":%q}`, id, id),
		fmt.Sprintf(`{"subject_type":"product","subject_id":%q,"unknown":true}`, id),
		fmt.Sprintf(`{"Subject_type":"product","subject_id":%q}`, id),
	} {
		postRaw(t, s, secret, "/v1/reports/anomaly", fmt.Sprint(i), []byte(body), 400)
	}
}
