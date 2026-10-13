package postgres

import (
	"os"
	"testing"
)

func executeOIDCRequestMigration(t *testing.T, store *Store, direction string) error {
	t.Helper()
	statement, err := os.ReadFile("../../../migrations/20261013000100_oidc_authentication_requests." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(t.Context(), string(statement))
	return err
}
func oidcMigrationHistory(t *testing.T, store *Store) string {
	t.Helper()
	var result string
	if err := store.pool.QueryRow(t.Context(), `SELECT jsonb_build_array((SELECT jsonb_agg(p ORDER BY id) FROM sso_providers p),(SELECT jsonb_agg(s ORDER BY id) FROM sso_sessions s),(SELECT jsonb_agg(a ORDER BY sequence) FROM audit_chain_entries a))::text`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestPostgresOIDCRequestMigrationPreservesIdentityHistoryAndGuardsRetainedState(t *testing.T) {
	store, _, request := oidcRequestStorageFixture(t)
	before := oidcMigrationHistory(t, store)
	if err := executeOIDCRequestMigration(t, store, "down"); err == nil {
		t.Fatal("downgrade discarded retained authentication state")
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests WHERE id=$1`, request.ID).Scan(&count); err != nil || count != 1 || oidcMigrationHistory(t, store) != before {
		t.Fatal("guarded downgrade changed request or identity history", err)
	}
	// Only this disposable fixture's operational request is removed to exercise
	// the empty-schema rollback and populated provider/session upgrade path.
	if _, err := store.pool.Exec(t.Context(), `DELETE FROM oidc_authentication_requests WHERE id=$1`, request.ID); err != nil {
		t.Fatal(err)
	}
	if err := executeOIDCRequestMigration(t, store, "down"); err != nil {
		t.Fatal(err)
	}
	if oidcMigrationHistory(t, store) != before {
		t.Fatal("empty-state downgrade rewrote identity history")
	}
	if err := executeOIDCRequestMigration(t, store, "up"); err != nil {
		t.Fatal(err)
	}
	if oidcMigrationHistory(t, store) != before {
		t.Fatal("upgrade rewrote populated providers, sessions or audit history")
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests`).Scan(&count); err != nil || count != 0 {
		t.Fatal("upgrade manufactured login proof for historical sessions", err)
	}
}
