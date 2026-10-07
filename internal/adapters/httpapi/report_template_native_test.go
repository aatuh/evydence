package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReportTemplateStrictPreflightBeforeGuards(t *testing.T) {
	for _, render := range []bool{false, true} {
		t.Run(fmt.Sprintf("render=%t", render), func(t *testing.T) {
			base, secret := testServer(t)
			f := &reportTemplateHTTPFake{}
			s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{ReportTemplateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
			s.ledger, s.packages = nil, nil
			path, body, field := "/v1/report-templates", `{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":["subject_id"]}`, "name"
			extra := []string{`{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":null}`, `{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":[null]}`, `{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":["subject_id"],"template":null}`}
			if render {
				path, body, field = "/v1/report-templates/template/render", `{"subject_type":"label","subject_id":"label-only"}`, "subject_id"
				extra = []string{`{"subject_type":null,"subject_id":"label-only"}`}
			}
			bad := []string{"", " ", "{", "null", "[]", "{}", body + " {}", string([]byte{0xff}), strings.Replace(body, `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1), strings.TrimSuffix(body, "}") + `,"extra":true}`, strings.TrimSuffix(body, "}") + `,"` + field + `":null}`, strings.Replace(body, `"`+field+`":"`, `"`+field+`":"bad\u0000`, 1)}
			for n, v := range append(bad, extra...) {
				postRaw(t, s, secret, path, fmt.Sprintf("invalid-%d", n), []byte(v), 400)
				if f.creates+f.renders+f.createGuards+f.renderGuards != 0 {
					t.Fatal("malformed report input reached guard or command", f)
				}
			}
		})
	}
}

func TestReportTemplateCookieOriginAndBearerPrecedenceAcrossFixturePorts(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, render := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%t/render=%t", native, render), func(t *testing.T) {
				base, secret := testServer(t)
				f := &reportTemplateHTTPFake{}
				path, body := "/v1/report-templates", `{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":["subject_id"]}`
				if render {
					v := postJSON(t, base, secret, path, "parent", map[string]any{"name": "Definition", "version": "1", "report_type": "metadata", "allowed_fields": []string{"subject_id"}}, 201)
					path, body = "/v1/report-templates/"+dataField(t, v, "id")+"/render", `{"subject_type":"label","subject_id":"label-only"}`
				}
				s := base
				if native {
					var err error
					s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{ReportTemplateCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
					if err != nil {
						t.Fatal(err)
					}
					s.ledger, s.packages = nil, nil
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
					before := f.creates + f.renders + f.createGuards + f.renderGuards
					s.Handler().ServeHTTP(w, r)
					if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != f.creates+f.renders+f.createGuards+f.renderGuards {
						t.Fatal("unsafe report cookie mutation", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}
