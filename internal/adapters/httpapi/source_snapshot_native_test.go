package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestSourceSnapshotNativeHandlersDoNotUseLedger(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		base, secret := testServer(t)
		f := &sourceSnapshotHTTPFake{}
		s, err := NewServerWithOptions(base.ledger, ServerOptions{SourceSnapshotCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
		if err != nil {
			t.Fatal(err)
		}
		s.ledger, s.idempotency = nil, nil
		path := "/v1/collectors/" + provider + "/source-snapshots"
		body := []byte(`{"repository":{"full_name":"org/api"},"branch":{"name":"main","protected":false}}`)
		one := postRaw(t, s, secret, path, "native", body, 201)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "native", body, 201))
		postRaw(t, s, secret, path, "native", append(append([]byte(nil), body...), ' '), 409)
		f.guardErr = errors.New("private-snapshot password=secret")
		out := postRaw(t, s, secret, path, "native", body, 500)
		if f.calls != 1 || f.guards != 4 || strings.Contains(out, "private-snapshot") || f.provider != provider || f.input.Branch == nil || f.input.Branch.Protected {
			t.Fatal("snapshot native boundary failed", f, out)
		}
	}
}

func TestSourceSnapshotMalformedInputStopsBeforeNativeGuard(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		for _, native := range []bool{false, true} {
			base, secret := testServer(t)
			s := base
			f := &sourceSnapshotHTTPFake{}
			if native {
				var err error
				s, err = NewServerWithOptions(base.ledger, ServerOptions{SourceSnapshotCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
				s.ledger, s.idempotency = nil, nil
			}
			path := "/v1/collectors/" + provider + "/source-snapshots"
			bad := []string{"", " ", "{", "null", "[]", "{} {}", string([]byte(`{"repository":{"full_name":"`)) + string([]byte{0xff}) + `"}}`, strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), `{"repository":{"full_name":"org/api"},"Repository":{"full_name":"other"}}`, `{"repository":{"full_name":"org/api"},"commit":{"sha":"invalid"}}`, `{"repository":{"full_name":"org/api"},"branch":{"name":""}}`, `{"repository":{"full_name":"org/api"},"pull_request":{"provider_id":"1","title":"T","state":"unknown"}}`, `{"repository":{"full_name":"org/api"},"project_id":"` + strings.Repeat(" ", 1025) + `project"}`, `{"repository":{"full_name":"org/api"},"branch":{"name":"` + strings.Repeat("x", 2305) + `"}}`, `{"repository":{"full_name":"bad\u0000"}}`}
			for i, body := range bad {
				out := postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(body), 400)
				if f.calls+f.guards != 0 || strings.Contains(out, `"data"`) {
					t.Fatal("malformed snapshot reached guard", native, f, out)
				}
			}
		}
	}
}

func TestSourceSnapshotCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		for _, native := range []bool{false, true} {
			base, secret := testServer(t)
			s := base
			f := &sourceSnapshotHTTPFake{}
			if native {
				var err error
				s, err = NewServerWithOptions(base.ledger, ServerOptions{SourceSnapshotCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, tc := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				path := "/v1/collectors/" + provider + "/source-snapshots"
				r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(fmt.Sprintf(`{"repository":{"full_name":"org/api%d"}}`, i)))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				before := f.calls + f.guards
				s.Handler().ServeHTTP(w, r)
				if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && f.calls+f.guards != before {
					t.Fatal("unsafe snapshot cookie mutation", provider, native, w.Code, w.Body.String())
				}
			}
		}
	}
}
