package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestDeploymentWritesRequireNativeReplayAndCurrentAuthority(t *testing.T) {
	for _, event := range []bool{false, true} {
		t.Run(map[bool]string{false: "environment", true: "event"}[event], func(t *testing.T) {
			base, secret := testServer(t)
			e, d := &environmentCommandHTTPFake{}, &deploymentHTTPFake{}
			o := ServerOptions{}
			path, body := "/v1/environments", `{"product_id":"product","name":"Production","kind":"production"}`
			if event {
				o.DeploymentCommands = d
				path = "/v1/deployments"
				body = `{"environment_id":"env","release_id":"release","status":"succeeded"}`
			} else {
				o.DeploymentEnvironmentCommands = e
			}
			if s, err := newLegacyServerFixtureWithOptions(base.ledger, o); err == nil || s != nil {
				t.Error("deployment write accepted aggregate replay")
			}
			o.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger = nil
			one := postRaw(t, s, secret, path, "original", []byte(body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "original", []byte(body), 201))
			e.guardErr, d.guardErr = application.ErrForbidden, application.ErrForbidden
			postRaw(t, s, secret, path, "original", []byte(body), 403)
			if e.calls+d.calls != 1 || e.guards+d.guards != 3 {
				t.Fatal("deployment replay skipped current authority", e, d)
			}
		})
	}
}

func TestDeploymentCreationRejectsMalformedInputBeforeNativeGuard(t *testing.T) {
	for _, event := range []bool{false, true} {
		t.Run(map[bool]string{false: "environment", true: "event"}[event], func(t *testing.T) {
			base, secret := testServer(t)
			e, d := &environmentCommandHTTPFake{}, &deploymentHTTPFake{}
			s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{DeploymentEnvironmentCommands: e, DeploymentCommands: d, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
			s.ledger = nil
			path, body, field := "/v1/environments", `{"product_id":"product","name":"Production","kind":"production"}`, "product_id"
			extra := []string{`{"product_id":"product","name":null,"kind":"production"}`, `{"product_id":"product","name":"Production","kind":null}`}
			if event {
				path, body, field = "/v1/deployments", `{"environment_id":"env","release_id":"release","status":"succeeded"}`, "environment_id"
				extra = []string{`{"environment_id":"env","release_id":"release","status":"succeeded","artifact_ids":null}`, `{"environment_id":"env","release_id":"release","status":"succeeded","artifact_ids":[null]}`, `{"environment_id":"env","release_id":"release","status":"succeeded","started_at":null}`, `{"environment_id":"env","release_id":"release","status":"succeeded","finished_at":null}`, `{"environment_id":"env","release_id":"release","status":"succeeded","started_at":"0001-01-01T00:00:00+01:00"}`, `{"environment_id":"env","release_id":"release","status":"invalid"}`}
			}
			bad := []string{"", " ", "{", "null", "[]", "{}", body + " {}", string([]byte{0xff}), strings.Replace(body, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1), strings.TrimSuffix(body, "}") + `,"extra":true}`, strings.TrimSuffix(body, "}") + `,"` + field + `":null}`, strings.Replace(body, `"`+field+`":"`, `"`+field+`":"bad\u0000`, 1), strings.Replace(body, `"`+field+`":"`, `"`+field+`":"`+strings.Repeat(" ", 1025), 1)}
			for n, invalid := range append(bad, extra...) {
				postRaw(t, s, secret, path, fmt.Sprintf("invalid-%d", n), []byte(invalid), 400)
				if e.calls+e.guards+d.calls+d.guards != 0 {
					t.Fatal("invalid deployment reached ownership or write", e, d)
				}
			}
		})
	}
}

func TestDeploymentCreationCookieOriginAndBearerPrecedenceAcrossFixturePorts(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, event := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%t/event=%t", native, event), func(t *testing.T) {
				base, secret := testServer(t)
				p := postJSON(t, base, secret, "/v1/products", "parent", map[string]any{"name": "Parent", "slug": "parent"}, 201)
				product := dataField(t, p, "id")
				path, body := "/v1/environments", fmt.Sprintf(`{"product_id":%q,"name":"Production","kind":"production"}`, product)
				if event {
					r := postJSON(t, base, secret, "/v1/releases", "release", map[string]any{"product_id": product, "version": "1"}, 201)
					e := postJSON(t, base, secret, "/v1/environments", "environment", map[string]any{"product_id": product, "name": "Production", "kind": "production"}, 201)
					path, body = "/v1/deployments", fmt.Sprintf(`{"environment_id":%q,"release_id":%q,"status":"succeeded"}`, dataField(t, e, "id"), dataField(t, r, "id"))
				}
				e, d := &environmentCommandHTTPFake{}, &deploymentHTTPFake{}
				s := base
				if native {
					var err error
					s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{DeploymentEnvironmentCommands: e, DeploymentCommands: d, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
					if err != nil {
						t.Fatal(err)
					}
					s.ledger = nil
				}
				for _, tc := range []struct {
					origin string
					bearer bool
					want   int
				}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
					r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(body))
					r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
					r.Header.Set("Origin", tc.origin)
					r.Header.Set("Idempotency-Key", "cookie-action")
					if tc.bearer {
						r.Header.Set("Authorization", "Bearer "+secret)
					}
					w := httptest.NewRecorder()
					before := e.calls + e.guards + d.calls + d.guards
					s.Handler().ServeHTTP(w, r)
					if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != e.calls+e.guards+d.calls+d.guards {
						t.Fatal("unsafe deployment cookie mutation", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}
