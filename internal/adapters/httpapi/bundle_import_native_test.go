package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func bundleImportNativeBody(t *testing.T) string {
	t.Helper()
	manifest := map[string]any{"bundle_version": "evidence-bundle.v1.0.0", "evidence_ids": []string{}}
	hash, err := application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"manifest": manifest, "manifest_hash": hash, "evidence_ids": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBundleImportStrictPreflightBeforeCurrentAuthority(t *testing.T) {
	base, secret := testServer(t)
	f := &bundleImportHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BundleImportCommand: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger = nil
	body := bundleImportNativeBody(t)
	bad := []string{"", " ", "{", "null", "[]", "{}", body + " {}", string([]byte{0xff}), strings.Replace(body, `"manifest_hash":`, `"Manifest_Hash":`, 1), strings.TrimSuffix(body, "}") + `,"extra":true}`}
	for _, field := range []string{"id", "tenant_id", "release_id", "evidence_ids", "manifest", "manifest_hash", "signature_refs", "verification_text", "schema_version", "created_at"} {
		bad = append(bad, strings.TrimSuffix(body, "}")+`,"`+field+`":null}`)
	}
	for _, extra := range []string{`"signature_refs":[null]`, `"signature_refs":["id\u0000"]`, `"id":"bad\u0000"`, `"tenant_id":"` + strings.Repeat("x", 1025) + `"`} {
		bad = append(bad, strings.TrimSuffix(body, "}")+","+extra+"}")
	}
	bad = append(bad, `{"manifest_hash":"hash","manifest":{"evidence_ids":["id"," id "]}}`, `{"manifest_hash":"hash","manifest":{"evidence_ids":[null]}}`, `{"manifest_hash":"hash","manifest":{"evidence_ids":[],"evidence_ids":["id"]}}`)
	for n, value := range bad {
		postRaw(t, s, secret, "/v1/evidence-bundles/import", fmt.Sprintf("invalid-%d", n), []byte(value), 400)
		if f.calls+f.guards != 0 {
			t.Fatal("malformed import reached guard or command", n, f)
		}
	}
}

func TestBundleImportCookieOriginAndBearerPrecedenceAcrossFixturePorts(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base, secret := testServer(t)
			f := &bundleImportHTTPFake{}
			s := base
			if native {
				var err error
				s, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BundleImportCommand: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
				s.ledger = nil
			}
			body := bundleImportNativeBody(t)
			for _, tc := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				r := httptest.NewRequest("POST", "https://api.example/v1/evidence-bundles/import", strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", "cookie-import")
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				before := f.guards + f.calls
				s.Handler().ServeHTTP(w, r)
				if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && before != f.guards+f.calls {
					t.Fatal("unsafe import cookie mutation", w.Code, w.Body.String())
				}
			}
		})
	}
}
