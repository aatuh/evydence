package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestArtifactImageRegistrationRequiresNativeReplayAndCurrentGuard(t *testing.T) {
	for _, kind := range []string{"artifact", "image"} {
		t.Run(kind, func(t *testing.T) {
			base, secret := testServer(t)
			a, i := &artifactHTTPFake{}, &containerImageHTTPFake{}
			o := ServerOptions{}
			path, body := "/v1/artifacts", `{"name":"Artifact","media_type":"text/plain","digest":"sha256:`+strings.Repeat("a", 64)+`","size":1}`
			if kind == "artifact" {
				o.ArtifactCommands = a
			} else {
				o.ContainerImageCommands = i
				path = "/v1/container-images"
				body = `{"repository":"registry.example.test/api","digest":"sha256:` + strings.Repeat("a", 64) + `"}`
			}
			if s, err := newLegacyServerFixtureWithOptions(base.ledger, o); err == nil || s != nil {
				t.Error("registration accepted aggregate replay")
			}
			o.DurableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger = nil // Native creation and replay must not access the aggregate.
			one := postRaw(t, s, secret, path, "current", []byte(body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "current", []byte(body), 201))
			a.guardErr, i.guardErr = application.ErrForbidden, application.ErrForbidden
			postRaw(t, s, secret, path, "current", []byte(body), 403)
			if a.calls+i.calls != 1 || a.guards+i.guards != 3 {
				t.Fatal("registration replay skipped current authority", a, i)
			}
		})
	}
}

func TestArtifactImageRegistrationPreflightRejectsMalformedInputBeforeCommands(t *testing.T) {
	for _, kind := range []string{"artifact", "image"} {
		t.Run(kind, func(t *testing.T) {
			base, secret := testServer(t)
			a, i := &artifactHTTPFake{}, &containerImageHTTPFake{}
			o := ServerOptions{DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
			path, field := "/v1/artifacts", "name"
			body := `{"name":"Artifact","media_type":"text/plain","digest":"sha256:` + strings.Repeat("a", 64) + `","size":1}`
			if kind == "artifact" {
				o.ArtifactCommands = a
			} else {
				o.ContainerImageCommands = i
				path, field = "/v1/container-images", "repository"
				body = `{"repository":"registry.example.test/api","digest":"sha256:` + strings.Repeat("a", 64) + `"}`
			}
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger = nil
			value := `"Artifact"`
			if kind == "image" {
				value = `"registry.example.test/api"`
			}
			bad := []string{`{`, `[]`, `null`, `{}`, body + `{}`, strings.Replace(body, value, `null`, 1), strings.Replace(body, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1), strings.Replace(body, value, `"bad\u0000text"`, 1), strings.Replace(body, value, `"`+strings.Repeat(" ", 65537)+`"`, 1), strings.Replace(body, value, value+`,"`+field+`":`+value, 1), strings.Replace(body, `"digest":`, `"unknown":true,"digest":`, 1)}
			if kind == "artifact" {
				for _, v := range []string{`null`, `-1`, `1.5`, `"1"`, `9223372036854775808`} {
					bad = append(bad, strings.Replace(body, `"size":1`, `"size":`+v, 1))
				}
			} else {
				bad = append(bad, strings.Replace(body, `"digest":`, `"artifact_id":null,"digest":`, 1))
			}
			for n, in := range bad {
				postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", n), []byte(in), 400)
			}
			if a.calls+a.guards+i.calls+i.guards != 0 {
				t.Fatal("invalid input reached authorization or writes", a, i)
			}
		})
	}
}

func TestArtifactImageRegistrationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base, secret := testServer(t)
			a, i := &artifactHTTPFake{}, &containerImageHTTPFake{}
			s := base
			if native {
				var err error
				s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{ArtifactCommands: a, ContainerImageCommands: i, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
				s.ledger = nil
			}
			for _, c := range []struct{ path, body string }{{"/v1/artifacts", `{"name":"A","media_type":"text/plain","digest":"sha256:` + strings.Repeat("a", 64) + `"}`}, {"/v1/container-images", `{"repository":"registry.example.test/api","digest":"sha256:` + strings.Repeat("a", 64) + `"}`}} {
				for n, tc := range []struct {
					origin string
					bearer bool
					want   int
				}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
					r := httptest.NewRequest("POST", "https://api.example"+c.path, strings.NewReader(c.body))
					r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
					r.Header.Set("Origin", tc.origin)
					r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", n))
					if tc.bearer {
						r.Header.Set("Authorization", "Bearer "+secret)
					}
					w := httptest.NewRecorder()
					before := a.calls + a.guards + i.calls + i.guards
					s.Handler().ServeHTTP(w, r)
					if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != a.calls+a.guards+i.calls+i.guards {
						t.Fatal("unsafe registration cookie mutation", c.path, w.Code, w.Body.String())
					}
				}
			}
		})
	}
}
