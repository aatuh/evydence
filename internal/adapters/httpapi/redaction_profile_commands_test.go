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

type redactionHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *redactionHTTPFake) AuthorizeCreateRedactionProfile(context.Context, identitydomain.Actor, packageapp.CreateRedactionProfileInput) error {
	f.guards++
	return f.guardErr
}
func (f *redactionHTTPFake) CreateRedactionProfile(_ context.Context, a identitydomain.Actor, in packageapp.CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	f.calls++
	return packagedomain.RedactionProfile{ID: "profile", TenantID: a.TenantID, Name: in.Name, Description: in.Description, AllowedTypes: in.AllowedTypes, ExcludedFields: in.ExcludedFields, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}, f.runErr
}

func TestRedactionHTTPRejectsMalformedInputBeforeCommand(t *testing.T) {
	base, secret := testServer(t)
	f := &redactionHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{RedactionProfileCommands: f}); err == nil {
		t.Fatal("redaction command lacks atomic replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{RedactionProfileCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)

	assertNoAggregateServerDependencies(t, s)
	const path = "/v1/redaction-profiles"
	for i, bad := range []string{"null", "[]", "{", `{} {}`, `{"name":null}`, `{"preset":"customer_safe","allowed_types":null}`, `{"preset":"customer_safe","excluded_fields":[null]}`, `{"preset":"customer_safe","unknown":true}`, `{"preset":"customer_safe","preset":"security_review"}`, `{"preset":"customer_safe","PRESET":null}`, `{"name":"Customer","allowed_types":[null]}`, `{"name":"Customer","allowed_types":[" "]}`, `{"name":"Customer","allowed_types":"sbom"}`, `{"name":"Customer","description":"bad\u0000","allowed_types":["sbom"]}`, `{"name":"` + string([]byte{0xff}) + `","allowed_types":["sbom"]}`, `{"preset":"customer_safe","allowed_types":["sbom"]}`, `{"name":"Customer","allowed_types":["` + strings.Repeat("x", 1025) + `"]}`, strings.Repeat(" ", 65537)} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("malformed input reached commands")
	}
	const body = `{"name":" Customer ","allowed_types":[" z ","sbom","sbom"],"excluded_fields":[" "]}`
	postRaw(t, s, "", path, "unauthorized", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	var response struct {
		Data map[string]any `json:"data"`
	}
	if json.Unmarshal([]byte(out), &response) != nil || response.Data["name"] != "Customer" || len(response.Data) != 6 || strings.Contains(out, `"excluded_fields"`) || strings.Contains(out, `"Name"`) || f.calls != 1 || f.guards != 1 {
		t.Fatal("public profile shape changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private profile SQL secret"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private profile SQL secret") || strings.Contains(out, `"profile"`) || stage == "guard" && f.calls != before {
				t.Fatal("backend error/guard leaked result", out)
			}
		}
	}
}

func TestRedactionHTTPBothProfilesRequireSafeCookieMutation(t *testing.T) {
	base, secret := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &redactionHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.RedactionProfileCommands = f
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
			r := httptest.NewRequest("POST", "https://example.com/v1/redaction-profiles", strings.NewReader(`{"name":"Customer","allowed_types":["sbom"]}`))
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
				t.Fatal("unsafe redaction cookie write", focused, w.Code, w.Body.String())
			}
		}
	}
}

func TestRedactionHTTPLocalReplayRechecksTenantGrant(t *testing.T) {
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
	const body = `{"preset":"customer_safe"}`
	first := postRaw(t, s, secret, "/v1/redaction-profiles", "replay", []byte(body), 201)
	if second := postRaw(t, s, secret, "/v1/redaction-profiles", "replay", []byte(body), 201); first != second {
		t.Fatal("local replay changed original result")
	}
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}
	postRaw(t, s, secret, "/v1/redaction-profiles", "replay", []byte(body), 403)
}

func TestRedactionOpenAPIBoundsCreationNotHistoricalResponse(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid contract")
	}
	in := doc.Components.Schemas["CreateRedactionProfileRequest"].Properties
	if in["name"]["maxLength"] != float64(65536) || in["description"]["maxLength"] != float64(65536) || in["allowed_types"]["maxItems"] != float64(1024) || in["excluded_fields"]["maxItems"] != float64(1024) || in["allowed_types"]["items"].(map[string]any)["maxLength"] != float64(1024) {
		t.Fatal("new-profile bounds missing", in)
	}
	if doc.Components.Schemas["RedactionProfile"].Properties["name"]["maxLength"] != nil {
		t.Fatal("historical response restricted")
	}
}
