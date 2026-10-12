package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

func TestDefaultTransportFixtureBootstrapsNativeRepositoryCredentials(t *testing.T) {
	server, secret := testServer(t)
	auth, ok := server.authn.(identityNativeFixtureAuthenticator)
	if !ok {
		t.Fatal("default transport fixture did not install native authentication")
	}
	keys, err := auth.APIKeysByPrefix(t.Context(), auth.credentials.Prefix(secret))
	if err != nil || len(keys) != 1 || keys[0].TenantID == "" || !auth.credentials.Equal(keys[0].Hash, auth.credentials.Hash(secret)) {
		t.Fatal("default transport fixture did not persist its real bootstrap credential", err)
	}
	actor, err := server.authn.Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID != keys[0].TenantID || actor.KeyID != keys[0].ID || !reflect.DeepEqual(actor.Scopes, keys[0].Scopes) {
		t.Fatal("default transport fixture did not authenticate current repository ownership", err)
	}
}

func TestSessionFixtureAPIKeyAuthenticationUsesCurrentRowsWithoutLedgerFallback(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	clock := application.ClockFunc(func() time.Time { return at })
	bootstrap := tenantBootstrapNativeFixture{base, fixtureSessionCredentials("current-pepper"), clock}
	tenant, key, secret, err := bootstrap.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &bundleWriteFailureFactory{base: base}
	cold := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "wrong-cached-pepper", UnitOfWork: factory, Now: func() time.Time { panic("session fixture used aggregate authentication clock") }})
	f := fixtureSessionAuthenticator(cold, "current-pepper", clock)
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	started := factory.begins
	actor, err := f.Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID != tenant.ID || actor.KeyID != key.ID || !reflect.DeepEqual(actor.Scopes, []string{"*"}) {
		t.Fatal("session fixture could not authenticate current API-key rows", err)
	}
	steps := factory.begins - started
	after, err := base.Snapshot()
	if err != nil || after.APIKeys[key.ID].LastUsedAt == nil || !after.APIKeys[key.ID].LastUsedAt.Equal(at) || !reflect.DeepEqual(before.AuditEntries, after.AuditEntries) || !reflect.DeepEqual(before.SigningKeys, after.SigningKeys) {
		t.Fatal("key activity did not commit independently or changed unrelated state", err)
	}
	if v, err := fixtureSessionAuthenticator(cold, "wrong-pepper", clock).Authenticate(t.Context(), secret); !errors.Is(err, app.ErrUnauthorized) || !reflect.DeepEqual(v, domain.Actor{}) {
		t.Fatal("session fixture accepted wrong credential pepper", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.Authenticate(ctx, secret); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, domain.Actor{}) {
		t.Fatal("cancelled authentication returned principal data", err)
	}
	factory.failAt = factory.begins + steps
	if v, err := f.Authenticate(t.Context(), secret); err == nil || !reflect.DeepEqual(v, domain.Actor{}) || factory.begins != factory.failAt {
		t.Fatal("activity commit failure returned principal or was not reached", err)
	}
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("denied/cancelled/failed authentication wrote state", err)
	}
}
