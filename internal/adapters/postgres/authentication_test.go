package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	application "github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresAuthenticationAPIKeyRevocationAndAtomicActivity(t *testing.T) {
	store := authenticationTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	credentials, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{"ten_auth", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, name, prefix, hash, scopes, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"key_auth", "ten_auth", "collector", credentials.Prefix("evy_secret"), credentials.Hash("evy_secret"), []byte(`["product:read"]`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, name, prefix, hash, scopes, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"key_other", "ten_other", "other", credentials.Prefix("evy_secret"), credentials.Hash("other-secret"), []byte(`["admin"]`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO collectors (id, tenant_id, name, type, version, api_key_id, status, allowed_scopes, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		"col_auth", "ten_auth", "collector", "custom", "1", "key_auth", "active", []byte(`["product:read"]`), "collector.v1", now); err != nil {
		t.Fatal(err)
	}
	authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{
		Reader: store, Activity: store, Credentials: credentials,
		Clock: application.ClockFunc(func() time.Time { return now }),
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authenticator.Authenticate(ctx, "Bearer evy_secret")
	if err != nil || actor.TenantID != "ten_auth" || actor.KeyID != "key_auth" || actor.CollectorID != "col_auth" || !actor.HasScope("product:read") || actor.HasScope("admin") {
		t.Fatalf("database API-key actor=%#v error=%v", actor, err)
	}
	var lastUsed, lastSeen sql.NullTime
	if err := store.pool.QueryRow(ctx, `SELECT last_used_at FROM api_keys WHERE id = 'key_auth'`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT last_seen_at FROM collectors WHERE id = 'col_auth'`).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid || !lastUsed.Time.Equal(now) || !lastSeen.Valid || !lastSeen.Time.Equal(now) {
		t.Fatalf("activity key=%v collector=%v", lastUsed, lastSeen)
	}
	key := identitydomain.APIKey{ID: "key_auth", TenantID: "ten_auth", Prefix: credentials.Prefix("evy_secret"), Hash: credentials.Hash("evy_secret")}
	later := now.Add(time.Minute)
	key.LastUsedAt = &later
	if err := store.RecordAPIKeyUse(ctx, key, identityapp.CollectorActivity{ID: "col_missing", TenantID: "ten_auth", LastSeenAt: later}); err == nil {
		t.Fatal("missing collector activity was accepted")
	}
	if err := store.pool.QueryRow(ctx, `SELECT last_used_at FROM api_keys WHERE id = 'key_auth'`).Scan(&lastUsed); err != nil || !lastUsed.Time.Equal(now) {
		t.Fatalf("failed collector update changed key activity: %v, %v", lastUsed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE api_keys SET revoked_at = $1 WHERE id = 'key_auth'`, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAPIKeyUse(ctx, key, identityapp.CollectorActivity{}); err == nil {
		t.Fatal("revoked key activity update was accepted")
	}
	if _, err := authenticator.Authenticate(ctx, "evy_secret"); !errors.Is(err, identityapp.ErrUnauthorized) || strings.Contains(err.Error(), "key_auth") {
		t.Fatalf("revoked key authentication error=%v", err)
	}
}

func TestPostgresAuthenticationSessionUsesCurrentTenantGrants(t *testing.T) {
	store := authenticationTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	credentials, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{"ten_auth", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO human_users (id, tenant_id, email, display_name, status, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"usr_auth", "ten_auth", "user@example.test", "User", "active", "human-user.v1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO role_bindings (id, tenant_id, subject_type, subject_id, role, resource_type, resource_id, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		"grant_own", "ten_auth", "user", "usr_auth", "release_manager", "product", "prod_own", "role-binding.v1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO role_bindings (id, tenant_id, subject_type, subject_id, role, resource_type, resource_id, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		"grant_foreign", "ten_other", "user", "usr_auth", "tenant_admin", "tenant", "ten_other", "role-binding.v1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sso_providers (id, tenant_id, name, type, issuer, client_id, groups_claim, role_mapping, status, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		"sso_auth", "ten_auth", "provider", "oidc", "https://issuer.example.test", "client", "groups", []byte(`{"security":"security_engineer"}`), "active", "sso-provider.v1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sso_sessions (id, tenant_id, user_id, provider_id, prefix, hash, groups, expires_at, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		"sess_auth", "ten_auth", "usr_auth", "sso_auth", credentials.Prefix("evysso_secret"), credentials.Hash("evysso_secret"), []byte(`["security"]`), now.Add(time.Hour), "sso-session.v1", now); err != nil {
		t.Fatal(err)
	}
	authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{
		Reader: store, Activity: store, Credentials: credentials,
		Clock: application.ClockFunc(func() time.Time { return now }),
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authenticator.Authenticate(ctx, "evysso_secret")
	if err != nil || actor.TenantID != "ten_auth" || actor.UserID != "usr_auth" || actor.SessionID != "sess_auth" || !actor.HasScope("project:read") || !actor.HasScope("security:read") || actor.HasScope("admin") || len(actor.ResourceGrants) != 2 {
		t.Fatalf("database session actor=%#v error=%v", actor, err)
	}
	if actor.ResourceGrants[0].ResourceID != "prod_own" || actor.ResourceGrants[1].ResourceType != "" {
		t.Fatalf("wrong session grant coordinates=%#v", actor.ResourceGrants)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM role_bindings WHERE id = 'grant_own'`); err != nil {
		t.Fatal(err)
	}
	actor, err = authenticator.Authenticate(ctx, "evysso_secret")
	if err != nil || actor.HasScope("project:read") || !actor.HasScope("security:read") || len(actor.ResourceGrants) != 1 {
		t.Fatalf("revoked role remained active: actor=%#v error=%v", actor, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at = $1 WHERE id = 'sess_auth'`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, "evysso_secret"); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatalf("revoked session error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at = NULL WHERE id = 'sess_auth'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE human_users SET status = 'inactive' WHERE id = 'usr_auth'`); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(ctx, "evysso_secret"); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatalf("deactivated user session error=%v", err)
	}
}

func TestPostgresAuthenticationHasActivePrefixIndexes(t *testing.T) {
	store := authenticationTestStore(t)
	checkIndexes := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `
		SELECT indexname, indexdef FROM pg_indexes
		WHERE schemaname = current_schema()
		  AND indexname IN ('api_keys_auth_prefix_idx', 'sso_sessions_auth_prefix_idx')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		indexes := map[string]string{}
		for rows.Next() {
			var name, definition string
			if err := rows.Scan(&name, &definition); err != nil {
				t.Fatal(err)
			}
			indexes[name] = definition
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"api_keys_auth_prefix_idx", "sso_sessions_auth_prefix_idx"} {
			definition := indexes[name]
			if want && (!strings.Contains(definition, "(prefix, id)") || !strings.Contains(definition, "revoked_at IS NULL")) {
				t.Fatalf("missing active credential prefix index %q: %q", name, definition)
			}
			if !want && definition != "" {
				t.Fatalf("down migration retained index %q: %q", name, definition)
			}
		}
	}
	checkIndexes(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260928000200_authentication_active_prefix_indexes.down.sql"},
		{file: "../../../migrations/20260928000200_authentication_active_prefix_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run index migration %q: %v", migration.file, err)
		}
		checkIndexes(migration.want)
	}
}

func authenticationTestStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "evydence_auth_query_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		admin.Close()
	})
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	return store
}
