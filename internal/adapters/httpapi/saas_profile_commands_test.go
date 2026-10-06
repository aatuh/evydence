package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type saasHTTPCommands struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *saasHTTPCommands) AuthorizeCreateSaaSProfile(context.Context, identitydomain.Actor, experimentalapp.SaaSProfileInput) error {
	f.guards++
	return f.guardErr
}
func (f *saasHTTPCommands) CreateSaaSProfile(_ context.Context, a identitydomain.Actor, in experimentalapp.SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error) {
	f.calls++
	return experimentaldomain.SaaSEditionProfile{ID: "profile", TenantID: a.TenantID, Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel, Status: "proposed", ConfigHash: "sha256:test", Limitations: []string{"intent only"}, SchemaVersion: experimentaldomain.SaaSEditionProfileVersion}, f.runErr
}
func saasHTTPFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	l := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	tenant, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(l)
	if err != nil {
		t.Fatal(err)
	}
	return s, secret, fmt.Sprintf(`{"name":"hosted","region":"eu","admin_tenant_id":%q,"isolation_model":"shared-control-plane"}`, tenant.ID)
}
func TestSaaSProfileHTTPFocusedStrictInputsAndPrivateFailures(t *testing.T) {
	base, secret, body := saasHTTPFixture(t)
	f := &saasHTTPCommands{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SaaSProfileCommands: f}); err == nil {
		t.Fatal("focused profiles bypass durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{SaaSProfileCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for i, bad := range []string{`null`, `[]`, `{}`, strings.Replace(body, `"hosted"`, `null`, 1), strings.Replace(body, `"name"`, `"Name"`, 1), strings.TrimSuffix(body, "}") + `,"name":"hosted"}`, strings.TrimSuffix(body, "}") + `,"unknown":true}`, body + ` {}`, strings.Replace(body, `"hosted"`, `"x\u0000"`, 1), strings.Replace(body, `"hosted"`, `"`+string([]byte{255})+`"`, 1), strings.Replace(body, `"hosted"`, `"`+strings.Repeat("x", 257)+`"`, 1), strings.Replace(body, `"eu"`, `" "`, 1)} {
		postRaw(t, s, secret, "/v1/saas/profiles", fmt.Sprint(i), []byte(bad), 400)
	}
	oversized := postRaw(t, s, secret, "/v1/saas/profiles", "body", []byte(strings.Repeat(" ", 128<<10)+body), 400)
	if !strings.Contains(oversized, `"field":"/body"`) || !strings.Contains(oversized, `"code":"invalid_size"`) || f.guards+f.calls != 0 {
		t.Fatal("unsafe input reached profile commands", oversized)
	}
	postRaw(t, s, "", "/v1/saas/profiles", "unauth", []byte(body), 401)
	out := postRaw(t, s, secret, "/v1/saas/profiles", "valid", []byte(body), 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"status":"proposed"`) || strings.Contains(out, `"AdminTenantID"`) {
		t.Fatal("profile wire contract changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{experimentalapp.ErrValidation, 400}, {experimentalapp.ErrNotFound, 404}, {experimentalapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private profile SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/saas/profiles", fmt.Sprintf("%s-%d", phase, i), []byte(body), ec.status)
			if strings.Contains(out, "private profile SQL") || strings.Contains(out, `"status":"proposed"`) || phase == "guard" && f.calls != before {
				t.Fatal("failed command leaked or published profile", out)
			}
		}
	}
}
func TestSaaSProfileHTTPLocalReplayRequiresCurrentInstanceAuthority(t *testing.T) {
	base, secret, body := saasHTTPFixture(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	postRaw(t, s, secret, "/v1/saas/profiles", "profile", []byte(body), 201)
	postRaw(t, s, secret, "/v1/saas/profiles", "profile", []byte(body), 201)
	auth.actor.Scopes = []string{"*"}
	postRaw(t, s, secret, "/v1/saas/profiles", "profile", []byte(body), 403)
	postRaw(t, s, secret, "/v1/saas/profiles", "new", []byte(body), 403)
	for i, bad := range []string{strings.TrimSuffix(body, "}") + `,"name":"hosted"}`, strings.TrimSuffix(body, "}") + `,"unknown":true}`} {
		postRaw(t, s, secret, "/v1/saas/profiles", fmt.Sprint(i), []byte(bad), 400)
	}
}
func TestSaaSProfileHTTPCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret, body := saasHTTPFixture(t)
	for _, focused := range []bool{false, true} {
		opts := ServerOptions{}
		if focused {
			opts.SaaSProfileCommands = &saasHTTPCommands{}
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example.test/v1/saas/profiles", strings.NewReader(body))
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
				t.Fatal("profile Origin or bearer precedence changed", focused, bearer, w.Code, w.Body.String())
			}
		}
	}
}
