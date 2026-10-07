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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlTemplateHTTPFake struct {
	calls, guards int
	err, guardErr error
	slug          string
}

func TestControlTemplateInstallRunsWithoutLedgerAndPreservesBodyFingerprints(t *testing.T) {
	base, secret := testServer(t)
	f := &controlTemplateHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{ControlTemplateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	path := "/v1/control-framework-template-packs/evydence-cra-readiness/install"
	for i, body := range []string{"", "{}", " \n\t"} {
		key := fmt.Sprintf("native-%d", i)
		one := postRaw(t, s, secret, path, key, []byte(body), 201)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, key, []byte(body), 201))
		postRaw(t, s, secret, path, key, []byte(body+" "), 409)
	}
	if f.calls != 3 || f.guards != 9 || f.slug != "evydence-cra-readiness" {
		t.Fatal("native install cloned Ledger or changed fingerprints", f)
	}
}

func TestControlTemplateInstallRejectsMalformedBodiesBeforeGuard(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &controlTemplateHTTPFake{}
		if native {
			s.controlTemplateCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
			s.ledger, s.idempotency = nil, nil
		}
		for i, body := range []string{"{", "[]", "null", `{"tenant_id":"other"}`, `{"tenant_id":null}`, `{"x":1,"x":2}`, "{} {}", "{} true", string([]byte{0xff}), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)} {
			out := postRaw(t, s, secret, "/v1/control-framework-template-packs/evydence-cra-readiness/install", fmt.Sprintf("bad-%d", i), []byte(body), 400)
			if f.calls+f.guards != 0 || strings.Contains(out, `"data"`) {
				t.Fatal("malformed install crossed guard", native, out, f)
			}
		}
	}
}

func (f *controlTemplateHTTPFake) AuthorizeControlTemplateInstallation(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}
func (f *controlTemplateHTTPFake) InstallControlFrameworkTemplatePack(_ context.Context, a identitydomain.Actor, slug string) (riskdomain.ControlFramework, error) {
	f.calls++
	f.slug = slug
	return riskdomain.ControlFramework{ID: "focused-framework", TenantID: a.TenantID, Slug: slug, Name: "Starter", Version: "1", Status: "active", SchemaVersion: riskdomain.ControlFrameworkSchemaVersion}, f.err
}

func TestControlTemplateInstallRequiresDurableExecutor(t *testing.T) {
	s, _ := testServer(t)
	if server, err := newLegacyServerFixtureWithOptions(s.ledger, ServerOptions{ControlTemplateCommands: &controlTemplateHTTPFake{}}); err == nil || server != nil {
		t.Fatal("focused template installation accepted Ledger replay")
	}
}

func TestControlTemplateSlugBoundsRawWhitespace(t *testing.T) {
	if err := validateControlTemplateSlug(strings.Repeat(" ", 1025) + "evydence-cra-readiness"); err == nil {
		t.Fatal("raw slug length checked only after trimming")
	}
}

func TestControlTemplateInstallChecksCurrentGuardOnReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &controlTemplateHTTPFake{}
	s.controlTemplateCommands = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	path := "/v1/control-framework-template-packs/evydence-cra-readiness/install"
	one := postRaw(t, s, secret, path, "install", nil, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "install", nil, 201))
	for _, tc := range []struct {
		err    error
		status int
	}{{riskapp.ErrForbidden, 403}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {errors.New("private-template SQL password=secret"), 500}} {
		f.guardErr = tc.err
		out := postRaw(t, s, secret, path, "install", nil, tc.status)
		if f.calls != 1 || strings.Contains(out, "private-template") || strings.Contains(out, `"data"`) {
			t.Fatal("template replay bypassed current tenant guard", out, f)
		}
	}
	if f.guards != 6 {
		t.Fatal("template replay skipped guard", f.guards)
	}
}

func TestControlTemplateInstallCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &controlTemplateHTTPFake{}
		if native {
			s.controlTemplateCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
			want := tc.status
			if native && want == 404 {
				want = 201
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/control-framework-template-packs/unknown/install", nil)
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.calls + f.guards
			s.Handler().ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Set-Cookie") != "" || want == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe template cookie mutation", native, w.Code, w.Body.String())
			}
		}
	}
}
