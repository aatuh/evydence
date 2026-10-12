package postgres

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func collectorAuthenticationStoreFixture(t *testing.T) (*Store, *identityapp.Authenticator, time.Time) {
	t.Helper()
	s := isolatedRelationalTestStore(t)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	c, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO tenants (id,name,created_at) VALUES ('tenant','Tenant',$1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO api_keys (id,tenant_id,name,prefix,hash,scopes,created_at) VALUES ('key','tenant','Collector',$1,$2,'["evidence:write"]',$3)`, c.Prefix("evy_test_secret"), c.Hash("evy_test_secret"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO collectors (id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version,created_at) VALUES ('collector','tenant','Collector','generic_ci','1','key','active','["evidence:write"]','collector.v1',$1)`, now); err != nil {
		t.Fatal(err)
	}
	a, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: s, Activity: s, Credentials: c, Clock: application.ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	return s, a, now
}

func requireNoCollectorAuthenticationHeartbeats(t *testing.T, s *Store) {
	t.Helper()
	var key, collector sql.NullTime
	if err := s.pool.QueryRow(t.Context(), `SELECT k.last_used_at,c.last_seen_at FROM api_keys k JOIN collectors c ON c.api_key_id=k.id AND c.tenant_id=k.tenant_id WHERE k.id='key'`).Scan(&key, &collector); err != nil {
		t.Fatal(err)
	}
	if key.Valid || collector.Valid {
		t.Fatal("denied collector authentication committed partial heartbeat", key.Valid, collector.Valid)
	}
}

func TestPostgresCollectorAuthenticationUsesCurrentStatusAndExactCapabilityBinding(t *testing.T) {
	s, a, _ := collectorAuthenticationStoreFixture(t)
	for _, tc := range []struct {
		name, status, keyScopes, allowed string
		success                          bool
	}{
		{"active narrower key", "active", `["evidence:write"]`, `["evidence:write","source:read"]`, true},
		{"disabled", "disabled", `["evidence:write"]`, `["evidence:write"]`, false},
		{"revoked", "revoked", `["evidence:write"]`, `["evidence:write"]`, false},
		{"broader key", "active", `["evidence:write","source:read"]`, `["evidence:write"]`, false},
		{"wildcard key", "active", `["*"]`, `["evidence:write"]`, false},
		{"changed binding", "active", `["evidence:write"]`, `["source:read"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), `UPDATE api_keys SET scopes=$1::jsonb,last_used_at=NULL WHERE id='key'`, tc.keyScopes); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(t.Context(), `UPDATE collectors SET status=$1,allowed_scopes=$2::jsonb,last_seen_at=NULL WHERE id='collector'`, tc.status, tc.allowed); err != nil {
				t.Fatal(err)
			}
			actor, err := a.Authenticate(t.Context(), "evy_test_secret")
			if tc.success {
				if err != nil || actor.TenantID != "tenant" || actor.KeyID != "key" || actor.CollectorID != "collector" || !reflect.DeepEqual(actor.Scopes, []string{"evidence:write"}) {
					t.Fatal("current binding lost or expanded actor", err)
				}
			} else {
				if !errors.Is(err, identityapp.ErrUnauthorized) || !reflect.DeepEqual(actor, identitydomain.Actor{}) {
					t.Fatal("invalid binding fell through to an ordinary API key", err)
				}
				requireNoCollectorAuthenticationHeartbeats(t, s)
			}
		})
	}
}

func TestPostgresCollectorActivityRejectsBindingAndCredentialDriftAtomically(t *testing.T) {
	s, _, now := collectorAuthenticationStoreFixture(t)
	for _, change := range []string{
		`UPDATE collectors SET status='disabled' WHERE id='collector'`,
		`UPDATE collectors SET status='revoked' WHERE id='collector'`,
		`UPDATE collectors SET allowed_scopes='["source:read"]' WHERE id='collector'`,
		`UPDATE api_keys SET scopes='["source:read"]' WHERE id='key'`,
	} {
		if _, err := s.pool.Exec(t.Context(), `UPDATE collectors SET status='active',allowed_scopes='["evidence:write"]',last_seen_at=NULL WHERE id='collector'`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(t.Context(), `UPDATE api_keys SET scopes='["evidence:write"]',last_used_at=NULL WHERE id='key'`); err != nil {
			t.Fatal(err)
		}
		keys, err := s.APIKeysByPrefix(t.Context(), "evy_test_sec")
		if err != nil || len(keys) != 1 {
			t.Fatal("credential snapshot", err, len(keys))
		}
		binding, found, err := s.CollectorByAPIKey(t.Context(), "tenant", "key")
		if err != nil || !found {
			t.Fatal("binding snapshot", err, found)
		}
		key := keys[0]
		key.LastUsedAt = &now
		if _, err := s.pool.Exec(t.Context(), change); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordAPIKeyUse(t.Context(), key, identityapp.CollectorActivity{ID: binding.ID, TenantID: binding.TenantID, LastSeenAt: now, AllowedScopes: binding.AllowedScopes}); !errors.Is(err, identityapp.ErrUnauthorized) {
			t.Fatal("stale credential or collector binding authorized heartbeat", err)
		}
		requireNoCollectorAuthenticationHeartbeats(t, s)
	}
}

func TestPostgresCollectorActivityRejectsEmptyDeclaredBindingWithoutEffects(t *testing.T) {
	s, _, now := collectorAuthenticationStoreFixture(t)
	keys, err := s.APIKeysByPrefix(t.Context(), "evy_test_sec")
	if err != nil || len(keys) != 1 {
		t.Fatal("key snapshot", err, len(keys))
	}
	key := keys[0]
	key.LastUsedAt = &now
	if _, err := s.pool.Exec(t.Context(), `UPDATE collectors SET allowed_scopes='[]' WHERE id='collector'`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAPIKeyUse(t.Context(), key, identityapp.CollectorActivity{ID: "collector", TenantID: "tenant", LastSeenAt: now, AllowedScopes: []string{}}); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("empty declaration was treated as a valid authentication binding", err)
	}
	requireNoCollectorAuthenticationHeartbeats(t, s)
}

func TestPostgresAuthenticationPreservesEmptyUnboundAPIKeyScopes(t *testing.T) {
	s, a, _ := collectorAuthenticationStoreFixture(t)
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM collectors WHERE id='collector' AND tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE api_keys SET scopes='[]' WHERE id='key'`); err != nil {
		t.Fatal(err)
	}
	actor, err := a.Authenticate(t.Context(), "evy_test_secret")
	if err != nil || actor.TenantID != "tenant" || actor.KeyID != "key" || actor.CollectorID != "" || len(actor.Scopes) != 0 {
		t.Fatal("scope snapshot comparison broke an inert unbound credential", err)
	}
}
