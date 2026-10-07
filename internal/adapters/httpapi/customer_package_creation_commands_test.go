package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type customerCreationHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
	actor            identitydomain.Actor
	input            packageapp.CreateCustomerPackageInput
	value            packagedomain.CustomerSecurityPackage
}

func (f *customerCreationHTTPFake) AuthorizeCreateCustomerSecurityPackage(_ context.Context, a identitydomain.Actor, in packageapp.CreateCustomerPackageInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}

func (f *customerCreationHTTPFake) CreateCustomerSecurityPackage(_ context.Context, a identitydomain.Actor, in packageapp.CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	f.calls++
	f.actor, f.input = a, in
	f.value = packagedomain.CustomerSecurityPackage{ID: "package", TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: in.RedactionProfileID, Title: in.Title, State: "generated", Manifest: map[string]any{"public": true}, ManifestHash: "sha256:fixture", ExpiresAt: in.ExpiresAt, SchemaVersion: packagedomain.CustomerPackageSchemaVersion, CreatedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	return f.value, f.runErr
}

func TestCustomerCreationHTTPFocusedPortAndStrictInput(t *testing.T) {
	base, secret := testServer(t)
	f := &customerCreationHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CustomerPackageCreationCommands: f}); err == nil {
		t.Fatal("focused customer creation silently used Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CustomerPackageCreationCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	// Any accidental route access to a broad compatibility dependency fails.
	assertNoAggregateServerDependencies(t, s)
	const path = "/v1/customer-packages"
	const body = `{"product_id":" product ","release_id":" release ","redaction_profile_id":" profile ","title":" Review ","expires_at":"2030-01-01T12:00:00+02:00"}`
	bad := []string{"", "null", "[]", "{", `{}`, `{} {}`, `{"unknown":true}`, strings.Repeat(" ", 65537)}
	for _, field := range []string{"product_id", "release_id", "redaction_profile_id", "title", "expires_at"} {
		var fields map[string]any
		if json.Unmarshal([]byte(body), &fields) != nil {
			t.Fatal("fixture")
		}
		for _, value := range []any{nil, 1, []string{"bad"}, map[string]any{"bad": true}} {
			fields[field] = value
			b, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			bad = append(bad, string(b))
		}
		bad = append(bad, strings.TrimSuffix(body, "}")+fmt.Sprintf(",%q:null}", strings.ToUpper(field)))
		bad = append(bad, strings.TrimSuffix(body, "}")+fmt.Sprintf(",%q:null}", field))
	}
	for _, tc := range []struct{ field, value string }{
		{"product_id", " "}, {"redaction_profile_id", " "}, {"title", " "},
		{"product_id", strings.Repeat(" ", 1024) + "p"}, {"release_id", strings.Repeat("x", 1025)}, {"redaction_profile_id", "bad\x00"},
		{"title", strings.Repeat("x", 4097)}, {"title", strings.Repeat("é", 2049)}, {"title", "bad\x00"},
		{"expires_at", "not-a-time"}, {"expires_at", "0000-01-01T00:00:00Z"}, {"expires_at", "0001-01-01T00:00:00+01:00"},
	} {
		var fields map[string]any
		if json.Unmarshal([]byte(body), &fields) != nil {
			t.Fatal("fixture")
		}
		fields[tc.field] = tc.value
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		bad = append(bad, string(b))
	}
	bad = append(bad, `{"product_id":"`+string([]byte{255})+`","redaction_profile_id":"profile","title":"Review","expires_at":"2030-01-01T00:00:00Z"}`)
	for i, input := range bad {
		postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(input), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid input reached customer commands")
	}
	postRaw(t, s, "", path, "unauthorized", []byte(body), 401)
	out := postRaw(t, s, secret, path, "valid", []byte(body), 201)
	var envelope struct {
		Data domain.CustomerSecurityPackage `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(envelope.Data, customerPackageFromAccess(f.value)) || f.guards != 1 || f.calls != 1 || f.actor.KeyID == "" || f.input.ProductID != "product" || f.input.ReleaseID != "release" || f.input.RedactionProfileID != "profile" || f.input.Title != "Review" || f.input.ExpiresAt.Location() != time.UTC {
		t.Fatal("focused command lost normalized input, actor or public response", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private customer SQL secret"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private customer SQL secret") || strings.Contains(out, `"manifest"`) || stage == "guard" && f.calls != before {
				t.Fatal("guard/error exposed package", out)
			}
		}
	}
}

func TestCustomerCreationHTTPBothProfilesCookieAndLocalReplay(t *testing.T) {
	base, secret := testServer(t)
	product := dataField(t, postJSON(t, base, secret, "/v1/products", "product", map[string]any{"name": "Product", "slug": "product"}, 201), "id")
	profile := dataField(t, postJSON(t, base, secret, "/v1/redaction-profiles", "profile", map[string]any{"preset": "customer_safe"}, 201), "id")
	body := fmt.Sprintf(`{"product_id":%q,"redaction_profile_id":%q,"title":"Review","expires_at":"2030-01-01T00:00:00Z"}`, product, profile)
	for _, focused := range []bool{false, true} {
		f := &customerCreationHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.CustomerPackageCreationCommands = f
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
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/customer-packages", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%t-%d", focused, i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			before := f.calls + f.guards
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe customer cookie mutation", focused, w.Code, w.Body.String())
			}
		}
		for i, bad := range []string{strings.Replace(body, `"title":"Review"`, `"title":null`, 1), strings.TrimSuffix(body, "}") + `,"TITLE":"Alias"}`, strings.TrimSuffix(body, "}") + `,"title":"Duplicate"}`} {
			postRaw(t, s, secret, "/v1/customer-packages", fmt.Sprintf("bad-local-%t-%d", focused, i), []byte(bad), 400)
		}
	}
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: product, Scopes: []string{"package:write"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	one := postRaw(t, s, secret, "/v1/customer-packages", "local-replay", []byte(body), 201)
	if two := postRaw(t, s, secret, "/v1/customer-packages", "local-replay", []byte(body), 201); one != two {
		t.Fatal("local replay changed original package")
	}
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/customer-packages", "local-replay", []byte(body), 403)
}
