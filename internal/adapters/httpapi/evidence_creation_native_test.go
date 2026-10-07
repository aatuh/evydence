package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenericEvidenceCreationStrictPreflightAndExactNumbers(t *testing.T) {
	base, secret := testServer(t)
	f := &evidenceCreationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceCreationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.evidenceIngestion, s.localEvidenceCreation = nil, nil, nil
	body := `{"type":"manual","title":"Evidence","payload_hash":"sha256:` + strings.Repeat("a", 64) + `"}`
	for n, bad := range []string{"", " ", "{", "null", "[]", "{}", body + " {}", string([]byte{0xff}), strings.Replace(body, `"type":`, `"TYPE":`, 1), strings.TrimSuffix(body, "}") + `,"type":null}`, strings.TrimSuffix(body, "}") + `,"metadata":null}`, strings.TrimSuffix(body, "}") + `,"metadata":{"bad":"value\u0000"}}`, strings.TrimSuffix(body, "}") + `,"subject_refs":[null]}`, strings.TrimSuffix(body, "}") + `,"subject_refs":[{"type":"artifact","ID":"artifact"}]}`, strings.TrimSuffix(body, "}") + `,"tags":[null]}`, strings.TrimSuffix(body, "}") + `,"observed_at":null}`, strings.TrimSuffix(body, "}") + `,"observed_at":"0001-01-01T00:00:00+01:00"}`, strings.TrimSuffix(body, "}") + `,"product_id":"` + strings.Repeat(" ", 1025) + `product"}`} {
		postRaw(t, s, secret, "/v1/evidence", fmt.Sprintf("invalid-%d", n), []byte(bad), 400)
		if f.calls+f.guards != 0 {
			t.Fatal("invalid evidence reached guard or command", f)
		}
	}
	valid := strings.TrimSuffix(body, "}") + `,"metadata":{"number":9007199254740993}}`
	postRaw(t, s, secret, "/v1/evidence", "number", []byte(valid), 201)
	if f.input.Metadata["number"] != json.Number("9007199254740993") {
		t.Fatal("evidence transport rounded metadata", f.input.Metadata)
	}
}

func TestGenericEvidenceCreationCookieOriginAndBearerPrecedenceBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base, secret := testServer(t)
			f := &evidenceCreationHTTPFake{}
			s := base
			if native {
				var err error
				s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceCreationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
				s.ledger, s.evidenceIngestion, s.localEvidenceCreation = nil, nil, nil
			}
			body := `{"type":"manual","title":"Evidence","payload_hash":"sha256:` + strings.Repeat("a", 64) + `"}`
			for _, tc := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				r := httptest.NewRequest("POST", "https://api.example/v1/evidence", strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", "cookie-action")
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				before := f.calls + f.guards
				s.Handler().ServeHTTP(w, r)
				if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != f.calls+f.guards {
					t.Fatal("unsafe evidence cookie mutation", w.Code, w.Body.String())
				}
			}
		})
	}
}
