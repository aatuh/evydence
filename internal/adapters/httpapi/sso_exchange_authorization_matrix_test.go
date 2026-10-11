package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestSSOExchangeRouteAuthorizationMatrix(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: peripheralFixtureQueryClock})
	owner, foreign := seedProviderVerificationFixture(t, ledger, "Owner"), seedProviderVerificationFixture(t, ledger, "Foreign")
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	trust := ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
	provider, err := trust.UpdateSSOProviderTrustMaterial(t.Context(), owner.actor, owner.provider.ID, identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "exchange-policy", "x": base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}}}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.ssoExchangeCommands = ssoSessionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}
	s.authn = &configuredAuthenticator{actor: domain.Actor{TenantID: owner.actor.TenantID, KeyID: "admin", Scopes: []string{"*", "admin", "identity:admin"}}}
	claims := func() map[string]any {
		return map[string]any{"iss": provider.Issuer, "aud": provider.ClientID, "sub": "subject-Owner", "email": owner.user.Email, "email_verified": true, "groups": []string{"token-reviewers"}, "exp": peripheralFixtureQueryClock().Add(time.Hour).Unix()}
	}
	request := func(t *testing.T, providerID, subject, token string, want int) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"provider_id": providerID, "subject": subject, "id_token": token})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer fixture-admin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), token) {
			t.Fatalf("exchange status=%d want=%d or input credential leaked", w.Code, want)
		}
		if want != 201 && (w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), `"data"`) || strings.Contains(w.Body.String(), `"secret"`)) {
			t.Fatal("denied identity acquired a cookie, secret or public result")
		}
		return w
	}
	token := signedRouterIDToken(t, private, "exchange-policy", claims())
	for i := 0; i < 2; i++ {
		before, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		w := request(t, provider.ID, "subject-Owner", token, 201)
		var response struct {
			Data struct {
				Verification domain.ProviderVerification `json:"verification"`
				Session      domain.SSOSession           `json:"session"`
				Secret       string                      `json:"secret"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Data.Secret == "" || response.Data.Session.TenantID != owner.actor.TenantID || response.Data.Session.UserID != owner.user.ID || response.Data.Session.ProviderID != provider.ID || response.Data.Session.Hash != "" || response.Data.Verification.Result != "passed" {
			t.Fatal("verified exchange lost bound session or safe public metadata", err)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Value != response.Data.Secret || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/v1" || !cookies[0].Expires.Equal(response.Data.Session.ExpiresAt) {
			t.Fatal("session cookie does not match its bound lifetime/security contract")
		}
		after, err := factory.Snapshot()
		if err != nil || len(after.SSOSessions) != len(before.SSOSessions)+1 || len(after.ProviderVerifications) != len(before.ProviderVerifications)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || len(after.Idempotency) != len(before.Idempotency) || strings.Contains(exchangeTestSnapshotString(t, after), token) || strings.Contains(exchangeTestSnapshotString(t, after), response.Data.Secret) {
			t.Fatal("exchange became replay, stored a secret, or lost atomic effects", err)
		}
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		want int
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://foreign.example.test" }, 422},
		{"audience", func(c map[string]any) { c["aud"] = "foreign-client" }, 422},
		{"subject", func(c map[string]any) { c["sub"] = "subject-Foreign" }, 422},
		{"expiry", func(c map[string]any) { c["exp"] = peripheralFixtureQueryClock().Unix() }, 422},
		{"email", func(c map[string]any) { c["email_verified"] = false }, 422},
		{"capabilities", func(c map[string]any) { c["groups"] = []string{} }, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			c := claims()
			tc.edit(c)
			request(t, provider.ID, "subject-Owner", signedRouterIDToken(t, private, "exchange-policy", c), tc.want)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before.SSOSessions, after.SSOSessions) || len(after.ProviderVerifications) != len(before.ProviderVerifications)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(before.Idempotency, after.Idempotency) {
				t.Fatal("denial did not commit only its safe assessment/audit", err)
			}
		})
	}
	request(t, foreign.provider.ID, "subject-Foreign", token, 422)
	request(t, provider.ID, "subject-Foreign", token, 422)
	request(t, provider.ID, "subject-Owner", "malformed-credential-canary", 422)
	final, err := factory.Snapshot()
	if err != nil || len(final.SSOSessions) != 2 || strings.Contains(exchangeTestSnapshotString(t, final), token) || strings.Contains(exchangeTestSnapshotString(t, final), "malformed-credential-canary") {
		t.Fatal("foreign or unverified identity acquired a session or leaked a credential", err)
	}
}

func exchangeTestSnapshotString(t *testing.T, v app.MemoryUnitOfWorkSnapshot) string {
	t.Helper()
	// Inspect every record the exchange can write; replay is separately
	// compared because its composite-key map is not JSON serializable.
	raw, err := json.Marshal([]any{v.ProviderVerifications, v.SSOSessions, v.AuditEntries})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
