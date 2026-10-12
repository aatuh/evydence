package postgres

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresWorkerVEXDecisionHistoryProjectsSupersessionsInScope(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other');
		INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,vulnerability,status,justification,internal_notes,source,superseded_by,schema_version)VALUES
		('root','tenant','finding','scan','CVE-TEST','fixed','Review','private marker','manual',NULL,'decision.v1'),
		('legacy-root','tenant','legacy-finding','scan','CVE-LEGACY','fixed','Review',NULL,'manual','legacy-next','decision.v1'),
		('legacy-next','tenant','legacy-finding','scan','CVE-LEGACY','affected','Review',NULL,'manual',NULL,'decision.v1'),
		('unrelated','tenant','unrelated-finding','scan','CVE-OTHER','fixed','Review',NULL,'manual',NULL,'decision.v1'),
		('foreign','other','finding','scan','CVE-TEST','fixed','Review','foreign notes','manual',NULL,'decision.v1')`); err != nil {
		t.Fatal(err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_decision_supersessions(tenant_id,finding_id,predecessor_id,successor_id,created_at,schema_version)VALUES('tenant','finding','root','current',now(),'decision-supersession.v1');
		INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,vulnerability,status,justification,source,supersedes,schema_version)VALUES('current','tenant','finding','scan','CVE-TEST','affected','Review','manual','root','decision.v1')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant", "other"} {
		state := app.PersistedState{Scans: map[string]domain.VulnerabilityScan{"scan": {Findings: []domain.VulnerabilityFinding{{ID: "finding"}, {ID: "legacy-finding"}}}}, Decisions: map[string]domain.VulnerabilityDecision{}}
		readTx, err := store.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = loadWorkerVEXFindingDecisions(ctx, readTx, tenant, &state)
		_ = readTx.Rollback(context.WithoutCancel(ctx))
		if err != nil {
			t.Fatal(err)
		}
		if tenant == "tenant" {
			if len(state.Decisions) != 4 || state.Decisions["root"].SupersededBy != "current" || state.Decisions["root"].InternalNotes != "private marker" || state.Decisions["current"].SupersededBy != "" || state.Decisions["legacy-root"].SupersededBy != "legacy-next" {
				t.Fatal("VEX worker lost current or legacy history, or read unrelated records", state.Decisions)
			}
		} else if len(state.Decisions) != 1 || state.Decisions["foreign"].TenantID != "other" {
			t.Fatal("VEX worker crossed the tenant boundary", state.Decisions)
		}
	}
}
