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

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type marketplaceHTTPCommands struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *marketplaceHTTPCommands) AuthorizeCreateMarketplaceCollector(context.Context, identitydomain.Actor, experimentalapp.MarketplaceCollectorInput) error {
	f.guards++
	return f.guardErr
}
func (f *marketplaceHTTPCommands) CreateMarketplaceCollector(_ context.Context, a identitydomain.Actor, in experimentalapp.MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error) {
	f.calls++
	v, err := experimentalapp.BuildMarketplaceCollector("collector", a.TenantID, in, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		return v, err
	}
	return v, f.runErr
}
func marketplaceHTTPFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	l := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(l)
	if err != nil {
		t.Fatal(err)
	}
	return s, secret, fmt.Sprintf(`{"name":" scanner ","provider":" example ","version":" 1 ","publisher":" team ","manifest_hash":"sha256:%s"}`, strings.Repeat("A", 64))
}
func TestMarketplaceCollectorHTTPFocusedStrictInputsAndPrivateFailures(t *testing.T) {
	base, secret, body := marketplaceHTTPFixture(t)
	f := &marketplaceHTTPCommands{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{MarketplaceCollectorCommands: f}); err == nil {
		t.Fatal("focused registration bypasses durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{MarketplaceCollectorCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for i, bad := range []string{`null`, `[]`, `{}`, strings.Replace(body, `" scanner "`, `null`, 1), strings.Replace(body, `"name"`, `"Name"`, 1), strings.TrimSuffix(body, "}") + `,"name":"scanner"}`, strings.TrimSuffix(body, "}") + `,"unknown":true}`, body + ` {}`, strings.Replace(body, `" scanner "`, `"x\u0000"`, 1), strings.Replace(body, `" scanner "`, `"`+string([]byte{255})+`"`, 1), strings.Replace(body, `" scanner "`, `"`+strings.Repeat(" ", 257)+`scanner"`, 1), strings.Replace(body, `" 1 "`, `"`+strings.Repeat("x", 129)+`"`, 1), strings.Replace(body, strings.Repeat("A", 64), strings.Repeat("A", 63), 1), strings.TrimSuffix(body, "}") + `,"signature_id":null}`, strings.TrimSuffix(body, "}") + `,"sbom_id":" "}`, strings.TrimSuffix(body, "}") + `,"scan_id":"` + strings.Repeat("x", 1025) + `"}`} {
		postRaw(t, s, secret, "/v1/marketplace-collectors", fmt.Sprint(i), []byte(bad), 400)
	}
	out := postRaw(t, s, secret, "/v1/marketplace-collectors", "body", []byte(strings.Repeat(" ", 128<<10)+body), 400)
	if !strings.Contains(out, `"field":"/body"`) || !strings.Contains(out, `"code":"invalid_size"`) || f.calls+f.guards != 0 {
		t.Fatal("unsafe request reached commands", out)
	}
	postRaw(t, s, "", "/v1/marketplace-collectors", "unauth", []byte(body), 401)
	out = postRaw(t, s, secret, "/v1/marketplace-collectors", "valid", []byte(body), 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"state":"registered"`) || !strings.Contains(out, `"name":"scanner"`) || strings.Contains(out, `"TenantID"`) || strings.Contains(out, `"signature_id"`) || !strings.Contains(out, strings.Repeat("A", 64)) {
		t.Fatal("metadata contract changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{experimentalapp.ErrValidation, 400}, {experimentalapp.ErrNotFound, 404}, {experimentalapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private marketplace SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/marketplace-collectors", fmt.Sprintf("%s-%d", phase, i), []byte(body), ec.status)
			if strings.Contains(out, "private marketplace SQL") || strings.Contains(out, `"state":"registered"`) || phase == "guard" && f.calls != before {
				t.Fatal("failed command leaked or published", out)
			}
		}
	}
}
func TestMarketplaceCollectorHTTPLocalReplayRequiresCurrentTenantGrant(t *testing.T) {
	base, secret, body := marketplaceHTTPFixture(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"collector:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	postRaw(t, s, secret, "/v1/marketplace-collectors", "collector", []byte(body), 201)
	postRaw(t, s, secret, "/v1/marketplace-collectors", "collector", []byte(body), 201)
	auth.actor.ResourceGrants[0].ResourceType, auth.actor.ResourceGrants[0].ResourceID = "product", "product"
	postRaw(t, s, secret, "/v1/marketplace-collectors", "collector", []byte(body), 403)
	postRaw(t, s, secret, "/v1/marketplace-collectors", "new", []byte(body), 403)
}
func TestMarketplaceCollectorHTTPCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret, body := marketplaceHTTPFixture(t)
	for _, focused := range []bool{false, true} {
		opts := ServerOptions{}
		if focused {
			opts.MarketplaceCollectorCommands = &marketplaceHTTPCommands{}
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example.test/v1/marketplace-collectors", strings.NewReader(body))
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
				t.Fatal("Origin/bearer policy changed", focused, bearer, w.Code, w.Body.String())
			}
		}
	}
}

func TestMarketplaceCollectorHTTPCreateSchemaDescribesBoundsWithoutRestrictingHistory(t *testing.T) {
	s, _, _ := marketplaceHTTPFixture(t)
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
	in := doc.Components.Schemas["CreateMarketplaceCollectorRequest"]
	if len(in.Required) != 5 {
		t.Fatal("optional evidence references became mandatory", in.Required)
	}
	for _, field := range []struct {
		name string
		max  int
	}{{"name", 256}, {"provider", 256}, {"publisher", 256}, {"version", 128}, {"manifest_hash", 128}, {"signature_id", 1024}, {"sbom_id", 1024}, {"scan_id", 1024}} {
		p := in.Properties[field.name]
		if p["type"] != "string" || p["maxLength"] != float64(field.max) || !strings.Contains(fmt.Sprint(p["description"]), "UTF-8") {
			t.Fatal("raw byte bounds missing", field.name, p)
		}
	}
	if in.Properties["manifest_hash"]["pattern"] != `^\s*sha256:[A-Fa-f0-9]{64}\s*$` {
		t.Fatal("digest schema differs from normalized contract")
	}
	if doc.Components.Schemas["MarketplaceCollector"].Properties["name"]["maxLength"] != nil {
		t.Fatal("new input limits retroactively restrict stored records")
	}
}
