package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestAPIKeyNativeFixturePreservesCompleteDTOSecretFreeReplayAndExpiry(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: clock.Now})
	_, _, adminSecret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server.bindAPIKeyFixtureResources("fixture-pepper", clock)
	body := `{"name":"New native key","scopes":["evidence:read"],"expires_at":"2026-10-07T17:00:00Z"}`
	first := postRaw(t, server, adminSecret, "/v1/api-keys", "native-key", []byte(body), 201)
	secret := nestedDataField(t, first, "secret")
	id := dataFieldFromNestedObject(t, first, "api_key", "id")
	saved, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	key := saved.APIKeys[id]
	if key.Hash != fixtureSessionCredentials("fixture-pepper").Hash(secret) || !key.CreatedAt.Equal(clock.at) {
		t.Fatal("native issuance lost credential binding or explicit clock")
	}
	key.Hash = ""
	want, err := json.Marshal(map[string]any{"data": map[string]any{"api_key": key, "secret": secret}, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), first)
	replay := postRaw(t, server, adminSecret, "/v1/api-keys", "native-key", []byte(body), 201)
	want, err = json.Marshal(map[string]any{"data": map[string]any{"api_key": key}, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), replay)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(saved, after) || strings.Contains(replay, secret) {
		t.Fatal("API-key replay reissued secret or changed state", err)
	}
	actor, err := server.authn.Authenticate(t.Context(), secret)
	if err != nil || actor.KeyID != id || actor.TenantID != key.TenantID || !reflect.DeepEqual(actor.Scopes, []string{"evidence:read"}) {
		t.Fatal("repository-only issued key did not authenticate", actor, err)
	}
	clock.at = clock.at.Add(time.Hour)
	if _, err := server.authn.Authenticate(t.Context(), secret); err == nil {
		t.Fatal("expired native key authenticated")
	}
	if strings.Contains(first, "hash") {
		t.Fatal("native issuance exposed credential hash")
	}
}

func TestAPIKeyNativeFixtureRebindingPreservesCredentialsClockAndExplicitAuthentication(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	s.bindAPIKeyFixtureResources("fixture-pepper", clock)
	command := s.apiKeyCommands.(apiKeyFixtureCommands)
	auth := s.authn.(identityNativeFixtureAuthenticator)
	second := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	s.bindLegacyLedgerFixture(second)
	newCommand, newAuth := s.apiKeyCommands.(apiKeyFixtureCommands), s.authn.(identityNativeFixtureAuthenticator)
	if newCommand.ledger != second || newCommand.clock != clock || newCommand.credentials != command.credentials || newAuth.ledger != second || newAuth.clock != clock || newAuth.credentials != auth.credentials {
		t.Fatal("rebinding lost native credential dependencies")
	}
	custom := &configuredAuthenticator{actor: domain.Actor{TenantID: "explicit", KeyID: "explicit"}}
	s.authn = custom
	s.bindAPIKeyFixtureResources("fixture-pepper", clock)
	if s.authn != custom {
		t.Fatal("resource binding replaced explicit authentication port")
	}
}
