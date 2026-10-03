package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEvidenceVerificationIndexesMigrateBothWays(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		for _, table := range []string{"sboms", "vulnerability_scans", "openapi_contracts", "vex_documents", "build_attestations"} {
			var definition string
			if err := store.pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1),'')`, table+"_tenant_evidence_id_idx").Scan(&definition); err != nil {
				t.Fatal(err)
			}
			if want && !strings.Contains(definition, "(tenant_id, evidence_id, id)") || !want && definition != "" {
				t.Fatalf("index %s: %q want=%v", table, definition, want)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{{"../../../migrations/20261001000300_evidence_verification_indexes.down.sql", false}, {"../../../migrations/20261001000300_evidence_verification_indexes.up.sql", true}} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatal(err)
		}
		check(migration.want)
	}
}
