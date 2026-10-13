package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSAMLHTTPConfiguresOwnedBindingAndExchangesSignedAPIProof(t *testing.T) {
	f := newSAMLSignedExchangeFixture(t)
	credentials, err := buildAuthenticationCredentials("exchange-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	operatorSecret := "evysso_" + strings.Repeat("A", 43)
	if _, err := f.pool.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('operator-session','tenant','user','provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(operatorSecret), credentials.Hash(operatorSecret)); err != nil {
		t.Fatal(err)
	}
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: f.store}, "exchange-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: f.store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return f.store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.SAMLProviderBindingCommands == nil || opts.SAMLAuthenticationRequestCommands == nil {
		t.Fatal("native HTTP lacks SAML ports", err)
	}
	canary := newAggregateLoadCanary(t, t.Context(), f.store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, key string, body []byte, authenticated bool, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(method, "https://api.example.test"+path, bytes.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+operatorSecret)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !canary.Intact(t.Context()) {
			t.Fatal("native SAML HTTP request failed or reloaded aggregate", path, w.Code)
		}
		return w.Body.Bytes()
	}
	const path = "/v1/sso/providers/provider/saml-binding"
	body := []byte(`{"recipient":"https://api.example.test/v1/sso/session-exchanges"}`)
	first := request("POST", path, "saml-binding", body, true, 200)
	replay := request("POST", path, "saml-binding", body, true, 200)
	var firstEnvelope, replayEnvelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(first, &firstEnvelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &replayEnvelope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstEnvelope.Data, replayEnvelope.Data) || strings.Contains(string(first), "CERTIFICATE") || strings.Contains(string(first), operatorSecret) {
		t.Fatal("binding replay changed metadata or leaked internal trust")
	}
	request("GET", path, "", nil, true, 200)
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,saml_signing_certificates)SELECT 'foreign-provider','other',name,type,issuer,client_id,status,schema_version,created_at,saml_signing_certificates FROM sso_providers WHERE id='provider'`); err != nil {
		t.Fatal(err)
	}
	request("POST", "/v1/sso/providers/foreign-provider/saml-binding", "foreign-saml-binding", body, true, 404)
	raw := request("POST", "/v1/sso/saml-authentication-requests", "", []byte(`{"provider_id":"provider"}`), false, 201)
	var created struct {
		Data struct {
			Request struct {
				ID, Recipient    string
				NameIDFormat     string `json:"name_id_format"`
				Issuer, Audience string
			} `json:"authentication_request"`
			State string `json:"state_secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.Data.State == "" || created.Data.Request.ID == "" || created.Data.Request.Recipient != "https://api.example.test/v1/sso/session-exchanges" {
		t.Fatal("SAML initiation lost public protocol context", err)
	}
	f.request = identitydomain.SAMLAuthenticationRequest{ID: created.Data.Request.ID, Recipient: created.Data.Request.Recipient, Issuer: created.Data.Request.Issuer, Audience: created.Data.Request.Audience, NameIDFormat: created.Data.Request.NameIDFormat}
	assertion := f.sign(t, f.assertion())
	exchange, err := json.Marshal(map[string]any{"provider_id": "provider", "subject": "subject", "saml_assertion": assertion, "authentication_request_id": f.request.ID, "state_secret": created.Data.State})
	if err != nil {
		t.Fatal(err)
	}
	before := f.counts(t)
	out := request("POST", "/v1/sso/session-exchanges", "", exchange, false, 201)
	if !strings.Contains(string(out), `"secret":"evysso_`) || strings.Contains(string(out), assertion) || strings.Contains(string(out), created.Data.State) || f.counts(t) != [5]int{before[0] + 1, before[1] + 1, before[2] + 3, before[3] + 1, before[4] + 1} {
		t.Fatal("native HTTP lost atomic SAML effects or leaked incoming proof")
	}
	request("POST", "/v1/sso/session-exchanges", "", exchange, false, 401)
	// Browser initiation never sends state through JSON, and exchange returns
	// its session credential only through the existing protected session cookie.
	r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/saml-authentication-requests", strings.NewReader(`{"provider_id":"provider","delivery":"browser"}`)).WithContext(t.Context())
	r.Header.Set("Origin", "https://api.example.test")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	browserCreated := created
	browserCreated.Data.State = ""
	if err := json.Unmarshal(w.Body.Bytes(), &browserCreated); err != nil || w.Code != 201 || browserCreated.Data.State != "" {
		t.Fatal("native browser initiation leaked state or failed", w.Code, err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-evydence_saml_state" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatal("native browser state cookie unsafe")
	}
	f.request = identitydomain.SAMLAuthenticationRequest{ID: browserCreated.Data.Request.ID, Recipient: browserCreated.Data.Request.Recipient, Issuer: browserCreated.Data.Request.Issuer, Audience: browserCreated.Data.Request.Audience, NameIDFormat: browserCreated.Data.Request.NameIDFormat}
	a := f.assertion()
	a.CreateAttr("ID", "_browser_assertion")
	browserBody, err := json.Marshal(map[string]any{"provider_id": "provider", "subject": "subject", "saml_assertion": f.sign(t, a), "authentication_request_id": f.request.ID, "delivery": "browser"})
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", bytes.NewReader(browserBody)).WithContext(t.Context())
	r.Header.Set("Origin", "https://api.example.test")
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	before = f.counts(t)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 || strings.Contains(w.Body.String(), `"secret":`) || strings.Contains(w.Body.String(), cookies[0].Value) || f.counts(t) != [5]int{before[0] + 1, before[1] + 1, before[2] + 3, before[3] + 1, before[4] + 1} {
		t.Fatal("native browser exchange leaked secret or lost atomic effects", w.Code)
	}
	seenState, seenSession := false, false
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-evydence_saml_state" {
			seenState = c.MaxAge < 0
		}
		if c.Name == "evydence_session" {
			seenSession = c.HttpOnly && c.Secure && c.Path == "/v1"
			if strings.Contains(w.Body.String(), c.Value) {
				t.Fatal("browser JSON leaked complete session credential")
			}
		}
		if c.Name == "__Host-evydence_oidc_state" {
			t.Fatal("SAML browser exchange changed OIDC state")
		}
	}
	if !seenState || !seenSession || !canary.Intact(t.Context()) {
		t.Fatal("native SAML browser cookie lifecycle or aggregate boundary failed")
	}
	if _, err := f.pool.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("POST", path, "saml-binding", body, true, 403)
}
