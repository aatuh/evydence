package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
)

func TestSourceWritesOpenAPIDeclaresNativeReplayAndCurrentAuthority(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range sourceNativeCases() {
		op := operationMap(t, asStringAnyMap(t, doc["paths"]), tc.path, "post")
		description, _ := op["description"].(string)
		for _, required := range []string{"native durable replay", "before reservation and completed replay", "Raw bounds", "before trimming", "Origin", "Local evaluation requires PostgreSQL", "there is no local-memory API path", "no outbox job"} {
			if !strings.Contains(description, required) {
				t.Fatal("missing native source contract", tc.path, required, description)
			}
		}
	}
}

func TestSourceWritesMalformedInputDoesNotReachNativeGuard(t *testing.T) {
	for _, tc := range sourceNativeCases() {
		base, secret := testServer(t)
		o := ServerOptions{DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
		counts, _ := tc.configure(&o)
		s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
		if err != nil {
			t.Fatal(err)
		}
		s.ledger, s.idempotency = nil, nil
		for i, bad := range []string{"", " ", "{", "null", "[]", "{} {}", string([]byte{0xff}), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), `{}`, strings.Replace(tc.body, `"repository_id":"repo"`, `"repository_id":null`, 1), strings.Replace(tc.body, `"repository_id":"repo"`, `"repository_id":"repo","repository_id":"duplicate"`, 1), strings.Replace(tc.body, `"repository_id":"repo"`, `"repository_id":"`+strings.Repeat(" ", 1025)+`repo"`, 1), strings.Replace(tc.body, `"repository_id":"repo"`, `"repository_id":"bad\u0000"`, 1)} {
			out := postRaw(t, s, secret, tc.path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
			if counts() != [2]int{} || strings.Contains(out, `"data"`) {
				t.Fatal("malformed source reached guard", tc.path, counts(), out)
			}
		}
	}
}

type sourceNativeCase struct {
	path, body string
	configure  func(*ServerOptions) (func() [2]int, func(error))
}

func sourceNativeCases() []sourceNativeCase {
	return []sourceNativeCase{
		{"/v1/source/commits", `{"repository_id":"repo","sha":"` + strings.Repeat("a", 40) + `","message":" exact sensitive message "}`, func(o *ServerOptions) (func() [2]int, func(error)) {
			f := &sourceCommitHTTPFake{}
			o.SourceCommitCommands = f
			return func() [2]int { return [2]int{f.calls, f.guards} }, func(err error) { f.guardErr = err }
		}},
		{"/v1/source/branches", `{"repository_id":"repo","name":"main","protected":false}`, func(o *ServerOptions) (func() [2]int, func(error)) {
			f := &sourceBranchHTTPFake{}
			o.SourceBranchCommands = f
			return func() [2]int { return [2]int{f.calls, f.guards} }, func(err error) { f.guardErr = err }
		}},
		{"/v1/source/pull-requests", `{"repository_id":"repo","provider_id":"17","title":"Change","state":"open"}`, func(o *ServerOptions) (func() [2]int, func(error)) {
			f := &pullRequestHTTPFake{}
			o.PullRequestCommands = f
			return func() [2]int { return [2]int{f.calls, f.guards} }, func(err error) { f.guardErr = err }
		}},
	}
}

func TestSourceWritesRequireNativeDurableExecutor(t *testing.T) {
	for _, tc := range sourceNativeCases() {
		base, _ := testServer(t)
		var o ServerOptions
		tc.configure(&o)
		if v, err := newLegacyServerFixtureWithOptions(base.ledger, o); err == nil || v != nil {
			t.Fatal("source write accepted aggregate replay", tc.path)
		}
	}
}

func TestSourceWritesCheckCurrentGuardBeforeReplay(t *testing.T) {
	for _, tc := range sourceNativeCases() {
		t.Run(tc.path, func(t *testing.T) {
			base, secret := testServer(t)
			o := ServerOptions{DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
			counts, deny := tc.configure(&o)
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			one := postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201))
			deny(application.ErrForbidden)
			out := postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 403)
			if counts() != [2]int{1, 3} || strings.Contains(out, `"data"`) || strings.Contains(out, "sensitive message") {
				t.Fatal("source replay bypassed current guard", counts(), out)
			}
		})
	}
}

func TestSourceWritesNativeHandlersDoNotUseLedger(t *testing.T) {
	for _, tc := range sourceNativeCases() {
		t.Run(tc.path, func(t *testing.T) {
			base, secret := testServer(t)
			o := ServerOptions{DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
			counts, deny := tc.configure(&o)
			s, err := newLegacyServerFixtureWithOptions(base.ledger, o)
			if err != nil {
				t.Fatal(err)
			}
			s.ledger, s.idempotency = nil, nil
			one := postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201))
			postRaw(t, s, secret, tc.path, "native", []byte(tc.body+" "), 409)
			deny(errors.New("private-source password=secret"))
			out := postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 500)
			if counts() != [2]int{1, 4} || strings.Contains(out, "private-source") || strings.Contains(out, "sensitive message") {
				t.Fatal("source native boundary failed", counts(), out)
			}
		})
	}
}

func TestSourceWritesCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, tc := range sourceNativeCases() {
		for _, native := range []bool{false, true} {
			base, secret := testServer(t)
			s := base
			if native {
				o := ServerOptions{DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)}
				tc.configure(&o)
				var err error
				s, err = newLegacyServerFixtureWithOptions(base.ledger, o)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, origin := range []struct {
				value  string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
				want := origin.want
				if native && want == 404 {
					want = 201
				}
				r := httptest.NewRequest("POST", "https://api.example"+tc.path, strings.NewReader(tc.body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", origin.value)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
				if origin.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != want || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("unsafe source cookie mutation", tc.path, native, w.Code, w.Body.String())
				}
			}
		}
	}
}
