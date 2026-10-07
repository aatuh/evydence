package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func nativeBuildBody() string {
	return `{"project_id":"project","release_id":"release","provider":"generic_ci","commit_sha":"` + strings.Repeat("a", 40) + `","status":"passed","started_at":"2026-10-02T12:00:00Z"}`
}

func TestBuildCreationNativeDoesNotUseLedger(t *testing.T) {
	base, secret := testServer(t)
	f := &buildCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BuildCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	one := postRaw(t, s, secret, "/v1/builds", "native", []byte(nativeBuildBody()), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/builds", "native", []byte(nativeBuildBody()), 201))
	postRaw(t, s, secret, "/v1/builds", "native", []byte(nativeBuildBody()+" "), 409)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("native build used aggregate or repeated creation", f)
	}
}

func TestBuildCreationRejectsMalformedInputBeforeNativeGuard(t *testing.T) {
	base, secret := testServer(t)
	f := &buildCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BuildCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	valid := nativeBuildBody()
	bad := []string{"", " ", "{", "null", "[]", "{} {}", string([]byte{0xff}), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), `{}`, strings.Replace(valid, `"project_id":"project"`, `"project_id":null`, 1), strings.Replace(valid, `"project_id":"project"`, `"project_id":"project","Project_ID":"other"`, 1), strings.Replace(valid, `"project_id":"project"`, `"project_id":"`+strings.Repeat(" ", 1025)+`project"`, 1), strings.Replace(valid, `"status":"passed"`, `"status":"unknown"`, 1), strings.TrimSuffix(valid, "}") + `,"run_attempt":-1}`, strings.TrimSuffix(valid, "}") + `,"outputs":[null]}`, strings.TrimSuffix(valid, "}") + `,"outputs":[{"digest":null}]}`, strings.TrimSuffix(valid, "}") + `,"finished_at":null}`, strings.TrimSuffix(valid, "}") + `,"provider_metadata":{"x":"bad\u0000"}}`}
	for i, body := range bad {
		out := postRaw(t, s, secret, "/v1/builds", fmt.Sprintf("bad-%d", i), []byte(body), 400)
		if f.calls+f.guards != 0 || strings.Contains(out, `"data"`) {
			t.Fatal("malformed build reached guard", f, out)
		}
	}
	for i, timestamp := range []string{"0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-12:00"} {
		body := strings.Replace(valid, "2026-10-02T12:00:00Z", timestamp, 1)
		postRaw(t, s, secret, "/v1/builds", fmt.Sprintf("utc-year-%d", i), []byte(body), 400)
		if f.calls+f.guards != 0 {
			t.Fatal("unrepresentable UTC build timestamp reached guard", f)
		}
	}
}

func TestBuildCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		base, secret := testServer(t)
		s := base
		f := &buildCreationHTTPFake{}
		if native {
			var err error
			s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BuildCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			want   int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
			want := tc.want
			if native && want == 404 {
				want = 201
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/builds", strings.NewReader(nativeBuildBody()))
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
				t.Fatal("unsafe build cookie mutation", native, w.Code, w.Body.String())
			}
		}
	}
}
