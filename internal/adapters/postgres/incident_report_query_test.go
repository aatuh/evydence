package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestReadIncidentReportKeepsCurrentTenantAndParentSnapshot(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_incident_a", "ten_incident_b"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenantID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id,tenant_id,name,slug,created_at) VALUES ($1,$2,$1,$1,$3)`, "prod_"+tenantID, tenantID, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id,tenant_id,product_id,version,state,created_at) VALUES ($1,$2,$3,'1.0.0','draft',$4)`, "rel_"+tenantID, tenantID, "prod_"+tenantID, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, incident := range []struct{ id, tenant, product, release string }{
		{"inc_a", "ten_incident_a", "prod_ten_incident_a", "rel_ten_incident_a"},
		{"inc_b", "ten_incident_b", "prod_ten_incident_b", "rel_ten_incident_b"},
		{"inc_mismatch", "ten_incident_a", "prod_ten_incident_a", "rel_ten_incident_b"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO incidents (id,tenant_id,product_id,release_id,title,severity,status,opened_at,schema_version,created_at) VALUES ($1,$2,$3,$4,$1,'high','open',$5,'incident.v1',$5)`, incident.id, incident.tenant, incident.product, incident.release, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO incident_timeline_events (id,tenant_id,incident_id,event_type,summary,evidence_id,occurred_at,schema_version,created_at) VALUES ($1,$2,$3,'detected',$1,$4,$5,'incident-timeline.v1',$5)`, "event_"+incident.id, incident.tenant, incident.id, "ev_"+incident.id, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO remediation_tasks (id,tenant_id,incident_id,release_id,title,owner,status,evidence_id,schema_version,created_at) VALUES ($1,$2,$3,$4,$1,'security','open',$5,'remediation-task.v1',$6)`, "task_"+incident.id, incident.tenant, incident.id, incident.release, "ev_"+incident.id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO incident_timeline_events (id,tenant_id,incident_id,event_type,summary,occurred_at,schema_version,created_at)
		VALUES ('event_foreign_child','ten_incident_b','inc_a','detected','foreign summary',$1,'incident-timeline.v1',$1)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO remediation_tasks (id,tenant_id,incident_id,title,owner,status,schema_version,created_at)
		VALUES ('task_foreign_child','ten_incident_b','inc_a','foreign task','other','open','remediation-task.v1',$1)
	`, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadIncidentReport(ctx, "ten_incident_a", "inc_a")
	if err != nil || snapshot.Incident.ID != "inc_a" || len(snapshot.Timeline) != 1 || snapshot.Timeline[0].ID != "event_inc_a" || len(snapshot.Tasks) != 1 || snapshot.Tasks[0].ID != "task_inc_a" {
		t.Fatalf("incident snapshot=%#v err=%v", snapshot, err)
	}
	for _, test := range []struct{ tenant, id string }{
		{"ten_incident_b", "inc_a"}, {"ten_incident_a", "inc_b"}, {"ten_incident_a", "inc_mismatch"},
	} {
		if result, err := store.ReadIncidentReport(ctx, test.tenant, test.id); !errors.Is(err, packagequery.ErrIncidentReportNotFound) || result.Incident.ID != "" {
			t.Fatalf("unsafe incident=%#v err=%v", result, err)
		}
	}
	query, err := packagequery.NewIncidentReport(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_incident_a", UserID: "usr_a", Scopes: []string{"incident:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_ten_incident_a", Scopes: []string{"incident:read"}}}}
	report, err := query.Report(ctx, actor, "inc_a")
	if err != nil || report.IncidentID != "inc_a" || len(report.LinkedEvidence) != 2 {
		t.Fatalf("authorized incident report=%#v err=%v", report, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_ten_incident_b"
	if _, err := query.Report(ctx, actor, "inc_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant err=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO incident_timeline_events (id,tenant_id,incident_id,event_type,summary,occurred_at,schema_version,created_at)
		SELECT 'event_capacity_' || n, 'ten_incident_a', 'inc_a', 'detected', 'bounded event', $1,
		       'incident-timeline.v1', $1
		FROM generate_series(1, $2::integer) AS n
	`, now, maxIncidentReportEntries); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadIncidentReport(ctx, "ten_incident_a", "inc_a"); !errors.Is(err, packagequery.ErrIncidentReportCapacity) || result.Incident.ID != "" {
		t.Fatalf("oversized timeline returned partial report=%#v err=%v", result, err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM incident_timeline_events WHERE tenant_id='ten_incident_a' AND incident_id='inc_a' AND id LIKE 'event_capacity_%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO remediation_tasks (id,tenant_id,incident_id,title,owner,status,schema_version,created_at)
		SELECT 'task_capacity_' || n, 'ten_incident_a', 'inc_a', 'bounded task', 'security', 'open',
		       'remediation-task.v1', $1
		FROM generate_series(1, $2::integer) AS n
	`, now, maxIncidentReportEntries); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadIncidentReport(ctx, "ten_incident_a", "inc_a"); !errors.Is(err, packagequery.ErrIncidentReportCapacity) || result.Incident.ID != "" {
		t.Fatalf("oversized tasks returned partial report=%#v err=%v", result, err)
	}
}

func TestIncidentReportBoundedReadIndexesMigrateBothWays(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		for name, columns := range map[string]string{
			"incident_timeline_events_report_order_idx": "(tenant_id, incident_id, occurred_at, id)",
			"remediation_tasks_report_order_idx":        "(tenant_id, incident_id, created_at, id)",
		} {
			var definition string
			if err := store.pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1),'')`, name).Scan(&definition); err != nil {
				t.Fatal(err)
			}
			if want && !strings.Contains(definition, columns) {
				t.Fatalf("missing report index %q: %q", name, definition)
			}
			if !want && definition != "" {
				t.Fatalf("down migration retained report index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20261001000100_incident_report_query_indexes.down.sql"},
		{file: "../../../migrations/20261001000100_incident_report_query_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}
