package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestNativeBootstrapTestExecutorKeepsFailedCommitsAndCancellationPrivate(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	factory := &bundleWriteFailureFactory{base: base}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "wrong-cached-pepper", UnitOfWork: factory, Now: func() time.Time { panic("bootstrap executor used aggregate clock") }})
	f := tenantBootstrapNativeFixture{credentials: fixtureSessionCredentials("fixture-pepper"), clock: providerVerificationFixtureClock()}
	tenant, key, secret, err := f.BootstrapTestTenant(t, ledger.ExecuteUnitOfWork, "Owner", "admin", []string{"*"})
	if err != nil || tenant.ID == "" || key.ID == "" || key.TenantID != tenant.ID || key.Hash != "" || secret == "" {
		t.Fatal("bootstrap executor failed real identity/signing commit or exposed hash", err)
	}
	before, err := base.Snapshot()
	if err != nil || len(before.Tenants) != 1 || len(before.APIKeys) != 1 || len(before.SigningKeys) != 1 || len(before.AuditEntries[tenant.ID]) != 1 || !f.credentials.Equal(before.APIKeys[key.ID].Hash, f.credentials.Hash(secret)) {
		t.Fatal("bootstrap executor did not commit the complete identity with explicit credentials", err)
	}
	factory.failAt = factory.begins + 1
	if tenant, key, secret, err := f.BootstrapTestTenant(t, ledger.ExecuteUnitOfWork, "Failure", "admin", []string{"*"}); err == nil || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" || factory.begins != factory.failAt {
		t.Fatal("bootstrap executor exposed partial identity or secret after real commit failure", err)
	}
	factory.failAt = 0
	for _, tc := range []struct {
		name    string
		err     error
		execute func(context.Context, app.UnitOfWorkCommand) error
	}{
		{"missing-executor", app.ErrValidation, nil},
		{"missing-audit", app.ErrValidation, func(ctx context.Context, command app.UnitOfWorkCommand) error {
			return ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
				r.Audit = nil
				return command(ctx, r)
			})
		}},
		{"cancelled-transaction", context.Canceled, func(parent context.Context, command app.UnitOfWorkCommand) error {
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			return ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
				cancel()
				return command(ctx, r)
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tenant, key, secret, err := f.BootstrapTestTenant(t, tc.execute, "Denied", "admin", []string{"*"}); !errors.Is(err, tc.err) || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" {
				t.Fatal("denied bootstrap executor returned identity or secret", err)
			}
		})
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed/cancelled bootstrap executor published partial state", err)
	}
}

func TestSharedScopeSeedsUseNativeIdentityWithoutAggregateCredentialsOrClock(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*testing.T, *repositoryFixture, string) domain.Actor
	}{
		{"evidence", func(t *testing.T, l *repositoryFixture, name string) domain.Actor {
			return seedEvidenceFixtureParents(t, l, name).actor
		}},
		{"integration", func(t *testing.T, l *repositoryFixture, name string) domain.Actor {
			return seedIntegrationFixtureScope(t, l, name).actor
		}},
		{"membership", func(t *testing.T, l *repositoryFixture, name string) domain.Actor {
			return seedMembershipFixtureScope(t, l, name).actor
		}},
		{"operations", func(t *testing.T, l *repositoryFixture, name string) domain.Actor {
			return seedOperationsFixtureParents(t, l, name).actor
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "wrong-cached-pepper", UnitOfWork: factory, Now: func() time.Time { panic("shared seed used aggregate identity clock") }})
			actor := tc.seed(t, ledger, "Owner")
			foreign := tc.seed(t, ledger, "Foreign")
			snapshot, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			at := providerVerificationFixtureClock().Now()
			for _, a := range []domain.Actor{actor, foreign} {
				key, found := snapshot.APIKeys[a.KeyID]
				if !found || a.TenantID == "" || key.TenantID != a.TenantID || snapshot.Tenants[a.TenantID].ID != a.TenantID || key.LastUsedAt == nil || !key.LastUsedAt.Equal(at) || !reflect.DeepEqual(a.Scopes, []string{"*"}) || len(snapshot.AuditEntries[a.TenantID]) == 0 {
					t.Fatal("shared seed lost current identity, credential activity or audit ownership")
				}
				keys := 0
				for _, k := range snapshot.SigningKeys {
					if k.TenantID == a.TenantID {
						keys++
					}
				}
				if keys != 1 {
					t.Fatal("shared seed did not commit initial signing material")
				}
			}
			if actor.TenantID == foreign.TenantID || actor.KeyID == foreign.KeyID {
				t.Fatal("shared seed reused another tenant's identity")
			}
		})
	}
}

func TestIdentityFixtureRebindingPreservesExplicitAuthenticator(t *testing.T) {
	server, secret := repositoryBootstrapTestServer(t)
	actor, err := server.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	explicit := &configuredAuthenticator{actor: actor}
	server.authn = explicit
	cold := newLegacyLedgerFixture(app.Config{APIKeyPepper: "unrelated-pepper"})
	server.bindLegacyLedgerFixture(cold)
	if server.authn != explicit {
		t.Fatal("fixture rebinding replaced an explicit authenticator with aggregate authority")
	}
}
