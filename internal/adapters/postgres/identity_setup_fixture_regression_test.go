package postgres

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

type identityFixtureCommitFailureFactory struct {
	app.UnitOfWorkFactory
	fail    bool
	commits int
}

func (f *identityFixtureCommitFailureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	uow, err := f.UnitOfWorkFactory.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return identityFixtureCommitFailureUnit{uow, f}, nil
}

type identityFixtureCommitFailureUnit struct {
	app.UnitOfWork
	factory *identityFixtureCommitFailureFactory
}

func (u identityFixtureCommitFailureUnit) Commit(ctx context.Context) error {
	u.factory.commits++
	if u.factory.fail {
		return errors.New("fixture final commit failure")
	}
	return u.UnitOfWork.Commit(ctx)
}

// This is real memory repository/transaction evidence for the outer fixture,
// not PostgreSQL locking, complete backup contents or restore evidence.
func TestPostgresIdentitySetupFixtureCommitsCurrentIdentityAndKeepsFailuresPrivate(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	factory := &identityFixtureCommitFailureFactory{UnitOfWorkFactory: base}
	f := postgresIdentitySetup(factory, "fixture-pepper")
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	f.clock = application.ClockFunc(func() time.Time { return at })
	tenant, key, secret, err := f.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil || tenant.ID == "" || key.ID == "" || key.TenantID != tenant.ID || key.Hash != "" || secret == "" || !tenant.CreatedAt.Equal(at) {
		t.Fatal("native PostgreSQL fixture setup lost identity or exposed stored hash", err)
	}
	snapshot, err := base.Snapshot()
	if err != nil || len(snapshot.Tenants) != 1 || len(snapshot.APIKeys) != 1 || len(snapshot.SigningKeys) != 1 || len(snapshot.AuditEntries[tenant.ID]) != 1 || !f.credentials.Equal(snapshot.APIKeys[key.ID].Hash, f.credentials.Hash(secret)) {
		t.Fatal("native fixture did not atomically bind real identity/audit/signing rows", err)
	}
	for _, signing := range snapshot.SigningKeys {
		if signing.TenantID != tenant.ID || signing.Version != 1 || signing.Status != "active" || len(signing.Private) != ed25519.PrivateKeySize || !signing.CreatedAt.Equal(at) {
			t.Fatal("native fixture lost complete initial signing material")
		}
	}
	public, err := json.Marshal(struct {
		Tenant domain.Tenant
		Key    domain.APIKey
	}{tenant, key})
	if err != nil || strings.Contains(string(public), secret) || strings.Contains(string(public), snapshot.APIKeys[key.ID].Hash) {
		t.Fatal("public fixture metadata leaked credential material", err)
	}
	actor, err := f.Authenticate(t.Context(), secret)
	if err != nil || actor.TenantID != tenant.ID || actor.KeyID != key.ID || !reflect.DeepEqual(actor.Scopes, []string{"*"}) {
		t.Fatal("native fixture could not authenticate committed current rows", err)
	}
	foreign, foreignKey, foreignSecret, err := f.BootstrapTenant(t.Context(), "Foreign", "admin", []string{"evidence:read"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.Authenticate(t.Context(), foreignSecret)
	if err != nil || other.TenantID != foreign.ID || other.KeyID != foreignKey.ID || other.TenantID == actor.TenantID || !reflect.DeepEqual(other.Scopes, []string{"evidence:read"}) {
		t.Fatal("native fixture authentication reused another tenant's identity or scopes", err)
	}
	before, err := base.Snapshot()
	if err != nil || before.APIKeys[key.ID].LastUsedAt == nil || !before.APIKeys[key.ID].LastUsedAt.Equal(at) {
		t.Fatal("native fixture authentication did not commit real activity", err)
	}
	wrong := postgresIdentitySetup(factory, "wrong-pepper")
	wrong.clock = f.clock
	if v, err := wrong.Authenticate(t.Context(), secret); !errors.Is(err, app.ErrUnauthorized) || !reflect.DeepEqual(v, domain.Actor{}) {
		t.Fatal("wrong-pepper fixture returned a principal", err)
	}
	factory.fail = true
	started := factory.commits
	if tenant, key, secret, err := f.BootstrapTenant(t.Context(), "Failure", "admin", []string{"*"}); err == nil || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" || factory.commits != started+1 {
		t.Fatal("failed real bootstrap commit exposed identity/secret or was not reached", err)
	}
	started = factory.commits
	if v, err := f.Authenticate(t.Context(), secret); err == nil || !reflect.DeepEqual(v, domain.Actor{}) || factory.commits != started+1 {
		t.Fatal("failed activity commit returned a principal or was not reached", err)
	}
	factory.fail = false
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if tenant, key, secret, err := f.BootstrapTenant(ctx, "Cancelled", "admin", []string{"*"}); !errors.Is(err, context.Canceled) || tenant != (domain.Tenant{}) || !reflect.DeepEqual(key, domain.APIKey{}) || secret != "" {
		t.Fatal("cancelled bootstrap exposed identity/secret", err)
	}
	if v, err := f.Authenticate(ctx, secret); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, domain.Actor{}) {
		t.Fatal("cancelled authentication returned a principal", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied/cancelled/failed fixture operation published partial state", err)
	}
}
