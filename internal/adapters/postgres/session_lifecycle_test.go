package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func sessionLifecycleFixture(t *testing.T) (*Store, identitydomain.SSOSession, *identityapp.HMACAuthenticationCredentials, string) {
	t.Helper()
	store := isolatedRelationalTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := c.GenerateSession()
	if err != nil {
		t.Fatal(err)
	}
	session := identitydomain.SSOSession{ID: "sess_lifecycle", TenantID: "ten_lifecycle", UserID: "usr_lifecycle", ProviderID: "sso_lifecycle", Prefix: credential.Prefix, Hash: credential.Hash, CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), SchemaVersion: identitydomain.SSOSessionSchemaVersion}
	for _, statement := range []string{
		`INSERT INTO tenants (id,name,created_at) VALUES ('ten_lifecycle','session fixture',now())`,
		`INSERT INTO human_users (id,tenant_id,email,display_name,status,schema_version,created_at) VALUES ('usr_lifecycle','ten_lifecycle','fixture@example.test','Fixture','active','human-user.v1',now())`,
		`INSERT INTO sso_providers (id,tenant_id,name,type,issuer,client_id,role_mapping,status,schema_version,created_at) VALUES ('sso_lifecycle','ten_lifecycle','fixture','oidc','https://issuer.example.test','fixture','{}','active','sso-provider.v1',now())`,
		`INSERT INTO role_bindings (id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at) VALUES ('grant_lifecycle','ten_lifecycle','user','usr_lifecycle','tenant_admin','tenant','ten_lifecycle','role-binding.v1',now())`,
	} {
		if _, err := store.pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(t.Context(), `INSERT INTO sso_sessions (id,tenant_id,user_id,provider_id,prefix,hash,groups,expires_at,schema_version,created_at) VALUES ($1,$2,$3,$4,$5,$6,'[]',$7,$8,$9)`, session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, session.Hash, session.ExpiresAt, session.SchemaVersion, session.CreatedAt); err != nil {
		t.Fatal(err)
	}
	return store, session, c, credential.Secret
}

type changingSessionIdentityReader struct {
	*Store
	change func()
}

func (r changingSessionIdentityReader) SessionIdentity(ctx context.Context, session identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	identity, err := r.Store.SessionIdentity(ctx, session)
	if err == nil {
		r.change()
	}
	return identity, err
}

func TestPostgresSessionAdmissionRejectsGrantChangedAfterLookup(t *testing.T) {
	store, session, credentials, secret := sessionLifecycleFixture(t)
	reader := changingSessionIdentityReader{Store: store, change: func() {
		if _, err := store.pool.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant_lifecycle'`); err != nil {
			t.Fatal(err)
		}
	}}
	authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: reader, Activity: store, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return session.CreatedAt })})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authenticator.Authenticate(t.Context(), secret)
	if !errors.Is(err, identityapp.ErrUnauthorized) || actor.UserID != "" {
		t.Fatalf("stale session grants admitted: error=%v", err)
	}
}
