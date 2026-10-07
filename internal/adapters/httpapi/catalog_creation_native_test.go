package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestCatalogCreationRequiresNativeReplayAndChecksCurrentAuthority(t *testing.T) {
	for _, kind := range []string{"product", "project", "release"} {
		t.Run(kind, func(t *testing.T) {
			base, secret := testServer(t)
			p, j, r := &productHTTPFake{}, &projectHTTPFake{}, &releaseCreationHTTPFake{}
			o := ServerOptions{}
			path, body := "", ""
			var counts func() (int, int)
			var deny func()
			switch kind {
			case "product":
				o.ProductCommands = p
				path = "/v1/products"
				body = `{"name":"Product","slug":"product"}`
				counts = func() (int, int) { return p.calls, p.guards }
				deny = func() { p.guardErr = application.ErrForbidden }
			case "project":
				o.ProjectCommands = j
				path = "/v1/projects"
				body = `{"product_id":"product","name":"Project"}`
				counts = func() (int, int) { return j.calls, j.guards }
				deny = func() { j.guardErr = application.ErrForbidden }
			case "release":
				o.ReleaseCreationCommands = r
				path = "/v1/releases"
				body = `{"product_id":"product","version":"1"}`
				counts = func() (int, int) { return r.calls, r.guards }
				deny = func() { r.guardErr = application.ErrForbidden }
			}
			if s, err := newLegacyServerFixtureWithOptions(base.ledger, o); err == nil || s != nil {
				t.Error("focused catalog creation accepted aggregate replay")
			}
			o.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger, s.idempotency = nil, nil
			one := postRaw(t, s, secret, path, "current", []byte(body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "current", []byte(body), 201))
			deny()
			postRaw(t, s, secret, path, "current", []byte(body), 403)
			if c, g := counts(); c != 1 || g != 3 {
				t.Fatal("catalog replay skipped current authority", c, g)
			}
		})
	}
}

func TestCatalogCreationRejectsMalformedJSONBeforeGuard(t *testing.T) {
	for _, kind := range []string{"product", "project", "release"} {
		t.Run(kind, func(t *testing.T) {
			base, secret := testServer(t)
			p, j, r := &productHTTPFake{}, &projectHTTPFake{}, &releaseCreationHTTPFake{}
			o := ServerOptions{ProductCommands: p, ProjectCommands: j, ReleaseCreationCommands: r, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			path, body, field := "/v1/products", `{"name":"N","slug":"s"}`, "name"
			if kind == "project" {
				path, body, field = "/v1/projects", `{"product_id":"product","name":"N"}`, "product_id"
			}
			if kind == "release" {
				path, body, field = "/v1/releases", `{"product_id":"product","version":"1"}`, "product_id"
			}
			for i, bad := range []string{"", " ", "{", "null", "[]", "{}", body + " {}", string([]byte{0xff}), strings.Replace(body, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1), strings.TrimSuffix(body, "}") + `,"extra":true}`, strings.TrimSuffix(body, "}") + `,"` + field + `":null}`, strings.Replace(body, `"N"`, `"bad\u0000"`, 1), strings.Replace(body, `"product"`, `"`+strings.Repeat(" ", 1025)+`product"`, 1)} {
				// Some variant-specific substitutions are unchanged valid input.
				if bad == body {
					continue
				}
				postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
				if p.calls+p.guards+j.calls+j.guards+r.calls+r.guards != 0 {
					t.Fatal("malformed catalog input reached guard or write", p, j, r)
				}
			}
		})
	}
}

func TestCatalogCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret := testServer(t)
	p, j, r := &productHTTPFake{}, &projectHTTPFake{}, &releaseCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{ProductCommands: p, ProjectCommands: j, ReleaseCreationCommands: r, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, body string }{{"/v1/products", `{"name":"N","slug":"s"}`}, {"/v1/projects", `{"product_id":"product","name":"N"}`}, {"/v1/releases", `{"product_id":"product","version":"1"}`}} {
		for i, tc := range []struct {
			origin string
			bearer bool
			want   int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			req := httptest.NewRequest("POST", "https://api.example"+c.path, strings.NewReader(c.body))
			req.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := p.calls + p.guards + j.calls + j.guards + r.calls + r.guards
			s.Handler().ServeHTTP(w, req)
			if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != p.calls+p.guards+j.calls+j.guards+r.calls+r.guards {
				t.Fatal("unsafe catalog cookie mutation", c.path, w.Code, w.Body.String())
			}
		}
	}
}
