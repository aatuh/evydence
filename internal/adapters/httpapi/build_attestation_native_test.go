package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestBuildAttestationNativeDoesNotUseLedgerAndUsesApplicationPayloadLimit(t *testing.T) {
	base, secret := testServer(t)
	f := &buildAttestationHTTPFake{}
	s, err := NewServerWithOptions(base.ledger, ServerOptions{BuildAttestationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	body := []byte(`{"payload":"recorded"}` + strings.Repeat(" ", int(app.SmallJSONRequestLimit)))
	path := "/v1/builds/build/attestations"
	one := postRaw(t, s, secret, path, "native", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "native", body, 201))
	postRaw(t, s, secret, path, "native", append(body, ' '), 409)
	if f.calls != 1 || f.guards != 3 || string(f.raw) != string(body) {
		t.Fatal("native upload used aggregate, changed bytes, or repeated ingestion", f)
	}
	before := f.guards
	postRaw(t, s, secret, path, "empty", nil, 400)
	postRaw(t, s, secret, path, "oversized", []byte(strings.Repeat(" ", int(releaseapp.BuildAttestationPayloadLimit)+1)), 400)
	if f.calls != 1 || f.guards != before {
		t.Fatal("oversized upload reached guard or parser", f)
	}
}

func TestBuildAttestationUploadUsesNativeUploadConcurrencyBudget(t *testing.T) {
	for _, path := range []string{"/v1/builds/build/attestations", "/v1/builds/encoded%2Fid/attestations"} {
		if !isNativeUploadRequest(httptest.NewRequest("POST", path, nil)) {
			t.Fatal("attestation bypassed upload concurrency budget", path)
		}
	}
	for _, path := range []string{"/v1/builds/build", "/v1/builds/build/attestations/extra", "/v1/builds//attestations"} {
		if isNativeUploadRequest(httptest.NewRequest("POST", path, nil)) {
			t.Fatal("unrelated route entered upload concurrency budget", path)
		}
	}
}

func TestBuildAttestationCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret := testServer(t)
	f := &buildAttestationHTTPFake{}
	s, err := NewServerWithOptions(base.ledger, ServerOptions{BuildAttestationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		origin string
		bearer bool
		want   int
	}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
		r := httptest.NewRequest("POST", "https://api.example/v1/builds/build/attestations", strings.NewReader(`{"payload":"recorded"}`))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Idempotency-Key", string(rune('a'+i)))
		if tc.bearer {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		before := f.calls + f.guards
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" || tc.want == 403 && f.calls+f.guards != before {
			t.Fatal("unsafe attestation cookie mutation", w.Code, w.Body.String())
		}
	}
}
