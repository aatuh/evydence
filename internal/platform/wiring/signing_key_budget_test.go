package wiring

import (
	"errors"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresSigningKeyRotationRejectsMetadataByteBudgetBeforeWrites(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('tenant','Key budget')`); err != nil {
		t.Fatal(err)
	}
	// Each field fits its individual bound and the row count is below 4096,
	// but the combined public metadata exceeds the independent 8 MiB budget.
	if _, err := pool.Exec(ctx, `INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,revocation_reason,created_at,valid_from,version,provider)
	 SELECT 'budget_'||n,'tenant','budget_'||n,'Ed25519','retiring',repeat('p',4000),repeat('r',4000),now(),now(),n,'local_ed25519' FROM generate_series(1,1600) AS n`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildSigningKeyCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"keys:admin"}}
	if result, err := commands.RotateSigningKey(ctx, actor, "bounded"); !errors.Is(err, verificationapp.ErrConflict) || result.ID != "" {
		t.Fatal("metadata overflow accepted", err)
	}
	var keys, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM signing_keys),(SELECT count(*) FROM audit_chain_entries)`).Scan(&keys, &audits); err != nil || keys != 1600 || audits != 0 {
		t.Fatal("overflow created state", err)
	}
}
