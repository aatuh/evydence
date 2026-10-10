package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

func TestTenantBootstrapNativeFixtureCommitsIdentityAuditAndSigningKeyWithoutAggregateClock(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	factory := &bundleWriteFailureFactory{base: base}
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	clock := application.ClockFunc(func() time.Time { return at })
	credentials := fixtureSessionCredentials("fixture-bootstrap-pepper")
	f := tenantBootstrapNativeFixture{factory, credentials, clock}
	tenant, key, secret, err := f.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil || tenant.ID == "" || key.ID == "" || key.TenantID != tenant.ID || secret == "" || key.Hash != "" || !tenant.CreatedAt.Equal(at) {
		t.Fatal("native bootstrap lost public identity or exposed stored hash", err)
	}
	snapshot, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tenants) != 1 || len(snapshot.APIKeys) != 1 || len(snapshot.SigningKeys) != 1 || len(snapshot.AuditEntries[tenant.ID]) != 1 || snapshot.AuditEntries[tenant.ID][0].EntryType != "tenant.created" || len(snapshot.OutboxJobs) != 0 {
		t.Fatal("identity/signing/audit bootstrap effects did not commit together")
	}
	stored := snapshot.APIKeys[key.ID]
	if !credentials.Equal(stored.Hash, credentials.Hash(secret)) || !reflect.DeepEqual(stored.Scopes, []string{"*"}) || stored.Prefix != credentials.Prefix(secret) {
		t.Fatal("committed bootstrap credential did not bind supplied pepper")
	}
	for _, signing := range snapshot.SigningKeys {
		if signing.TenantID != tenant.ID || signing.Version != 1 || signing.Status != "active" || signing.Algorithm != "Ed25519" || len(signing.Private) != ed25519.PrivateKeySize || !signing.CreatedAt.Equal(at) {
			t.Fatal("bootstrap signing material was missing, misbound or cleared before storage")
		}
		public, err := json.Marshal(signing)
		if err != nil || strings.Contains(string(public), "private") || strings.Contains(string(public), secret) || strings.Contains(string(public), stored.Hash) {
			t.Fatal("public signing metadata exposed bootstrap secrets", err)
		}
	}
	public, err := json.Marshal(struct {
		Tenant domain.Tenant `json:"tenant"`
		Key    domain.APIKey `json:"key"`
	}{tenant, key})
	if err != nil || strings.Contains(string(public), secret) || strings.Contains(string(public), stored.Hash) {
		t.Fatal("public bootstrap identity exposed credential material", err)
	}
	fresh := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "not-the-native-pepper", UnitOfWork: base, Now: func() time.Time { panic("authentication used aggregate clock") }})
	auth := fixtureIdentityAuthenticator(fresh, "fixture-bootstrap-pepper", clock)
	actor, err := auth.Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID != tenant.ID || actor.KeyID != key.ID || !reflect.DeepEqual(actor.Scopes, []string{"*"}) {
		t.Fatal("fresh authenticator did not use committed bootstrap rows", err)
	}
	if v, err := fixtureIdentityAuthenticator(fresh, "wrong-pepper", clock).Authenticate(t.Context(), secret); !errors.Is(err, app.ErrUnauthorized) || !reflect.DeepEqual(v, domain.Actor{}) {
		t.Fatal("wrong pepper authenticated or returned a partial principal", err)
	}
	beforeFailure, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.failAt = factory.begins + 1
	if tenant, key, secret, err := f.BootstrapTenant(t.Context(), "Failure", "admin", []string{"*"}); err == nil || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" || factory.begins != factory.failAt {
		t.Fatal("failed bootstrap commit exposed identity, signing material or bearer secret", err)
	}
	afterFailure, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(beforeFailure, afterFailure) {
		t.Fatal("failed bootstrap commit published partial effects", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if tenant, key, secret, err := f.BootstrapTenant(ctx, "Cancelled", "admin", []string{"*"}); !errors.Is(err, context.Canceled) || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" {
		t.Fatal("cancelled bootstrap returned data", err)
	}
	if tenant, key, secret, err := f.BootstrapTenant(t.Context(), "\x00invalid", "admin", []string{"*"}); !errors.Is(err, app.ErrValidation) || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" {
		t.Fatal("invalid bootstrap returned data", err)
	}
	unchanged, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(beforeFailure, unchanged) {
		t.Fatal("denied bootstrap changed stored state", err)
	}
}

func TestDerivedBootstrapServerFixturePreservesExplicitAuthenticationAndContext(t *testing.T) {
	base, secret := repositoryBootstrapTestServer(t)
	derived, err := derivedServerFixture(base, ServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := derived.authn.(identityNativeFixtureAuthenticator); !ok {
		t.Fatal("derived fixture restored cached authentication")
	}
	actor, err := derived.authn.Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID == "" || actor.KeyID == "" {
		t.Fatal("derived authenticator lost committed bootstrap principal", err)
	}
	explicit := &configuredAuthenticator{actor: actor}
	overridden, err := derivedServerFixture(base, ServerOptions{Authenticator: explicit})
	if err != nil || overridden.authn != explicit {
		t.Fatal("derived fixture replaced explicit authenticator", err)
	}
	var missingContext context.Context
	if server, err := derivedServerFixtureWithContext(missingContext, base, ServerOptions{}); err == nil || server != nil {
		t.Fatal("derived fixture accepted nil context")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if server, err := derivedServerFixtureWithContext(ctx, base, ServerOptions{}); !errors.Is(err, context.Canceled) || server != nil {
		t.Fatal("derived fixture accepted cancellation or returned partial server", err)
	}
}
