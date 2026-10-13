package postgres

import (
	"os"
	"testing"
)

func executeSAMLStateMigration(t *testing.T, store *Store, direction string) error {
	t.Helper()
	s, err := os.ReadFile("../../../migrations/20261013000200_saml_authentication_state." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(t.Context(), string(s))
	return err
}

func TestPostgresSAMLStateMigrationPreservesHistoryAndGuardsRetainedConfiguration(t *testing.T) {
	store, _, req, _ := samlRequestStorageFixture(t)
	before := oidcMigrationHistory(t, store)
	if err := executeSAMLStateMigration(t, store, "down"); err == nil {
		t.Fatal("downgrade discarded retained SAML configuration/state")
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM saml_authentication_requests WHERE id=$1`, req.ID).Scan(&count); err != nil || count != 1 || oidcMigrationHistory(t, store) != before {
		t.Fatal("guarded downgrade changed identity or login state", err)
	}
	// Remove only this disposable fixture's operational data to rehearse an
	// empty-state rollback; provider, session and audit history remains intact.
	if _, err := store.pool.Exec(t.Context(), `DELETE FROM saml_authentication_requests`); err != nil {
		t.Fatal(err)
	}
	if err := executeSAMLStateMigration(t, store, "down"); err == nil {
		t.Fatal("downgrade discarded a configured SP binding")
	}
	if _, err := store.pool.Exec(t.Context(), `DELETE FROM saml_provider_bindings`); err != nil {
		t.Fatal(err)
	}
	if err := executeSAMLStateMigration(t, store, "down"); err != nil {
		t.Fatal(err)
	}
	if oidcMigrationHistory(t, store) != before {
		t.Fatal("downgrade rewrote provider/session/audit history")
	}
	if err := executeSAMLStateMigration(t, store, "up"); err != nil {
		t.Fatal(err)
	}
	if oidcMigrationHistory(t, store) != before {
		t.Fatal("upgrade rewrote provider/session/audit history")
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM saml_authentication_requests`).Scan(&count); err != nil || count != 0 {
		t.Fatal("upgrade invented login authority for historical sessions", err)
	}
}
