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

func TestReadSecurityUpdateSnapshotKeepsCurrentTenantAndRelease(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_update_a", "ten_update_b"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id,tenant_id,name,slug,created_at) VALUES ($1,$2,$1,$1,$3)`, "prod_"+tenant, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id,tenant_id,product_id,version,state,created_at) VALUES ($1,$2,$3,'1.0.0','draft',$4)`, "rel_"+tenant, tenant, "prod_"+tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, release string }{
		{"scan_a", "ten_update_a", "rel_ten_update_a"},
		{"scan_b", "ten_update_b", "rel_ten_update_b"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ($1,$2,'document',$1,'test',$3,'evidence-item.v1','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, "ev_"+row.id, row.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings,created_at) VALUES ($1,$2,$3,$4,'scanner','target','{}'::jsonb,'[]'::jsonb,$5)`, row.id, row.tenant, "ev_"+row.id, row.release, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_vex_a','ten_update_a','document','vex','test',$1,'evidence-item.v1','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ev_dec_a", "ev_task_inc_a"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ($1,'ten_update_a','prod_ten_update_a','rel_ten_update_a','document',$1,'test',$2,'evidence-item.v1','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO vex_documents (id,tenant_id,evidence_id,release_id,format,author,statement_count,status_summary,schema_version,created_at) VALUES ('vex_a','ten_update_a','ev_vex_a','rel_ten_update_a','openvex','test',0,'{}'::jsonb,'vex.v1',$1)`, now); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, tenant, release, superseded string }{
		{"dec_a", "ten_update_a", "rel_ten_update_a", ""},
		{"dec_old", "ten_update_a", "rel_ten_update_a", "dec_a"},
		{"dec_b", "ten_update_b", "rel_ten_update_b", ""},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,impact_statement,source,evidence_id,evidence_ids,vex_document_id,superseded_by,internal_notes,schema_version,created_at) VALUES ($1,$2,$1,'scan_a',$3,'CVE-2026-0001','fixed','repaired','customer-safe','manual',$4,ARRAY[$4]::text[],$5,NULLIF($6,''),'private triage','decision.v1',$7)`, row.id, row.tenant, row.release, "ev_"+row.id, "vex_a", row.superseded, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, product, release string }{
		{"inc_a", "ten_update_a", "prod_ten_update_a", "rel_ten_update_a"},
		{"inc_b", "ten_update_b", "prod_ten_update_b", "rel_ten_update_b"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO incidents (id,tenant_id,product_id,release_id,title,severity,status,opened_at,schema_version,created_at) VALUES ($1,$2,$3,$4,$1,'high','open',$5,'incident.v1',$5)`, row.id, row.tenant, row.product, row.release, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO remediation_tasks (id,tenant_id,incident_id,title,owner,status,evidence_id,schema_version,created_at) VALUES ($1,$2,$3,$1,'security','open',$4,'task.v1',$5)`, "task_"+row.id, row.tenant, row.id, "ev_task_"+row.id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO remediation_tasks (id,tenant_id,incident_id,title,owner,status,schema_version,created_at) VALUES ('task_foreign_child','ten_update_b','inc_a','foreign','other','open','task.v1',$1)`, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadSecurityUpdateSnapshot(ctx, "ten_update_a", "prod_ten_update_a", "rel_ten_update_a")
	if err != nil || len(snapshot.ScanEvidenceIDs) != 1 || snapshot.ScanEvidenceIDs[0] != "ev_scan_a" || len(snapshot.Decisions) != 1 || snapshot.Decisions[0].ID != "dec_a" || snapshot.Decisions[0].InternalNotes != "" || snapshot.VEXEvidenceIDs["vex_a"] != "ev_vex_a" || len(snapshot.Incidents) != 1 || snapshot.Incidents[0].ID != "inc_a" || len(snapshot.Tasks) != 1 || snapshot.Tasks[0].ID != "task_inc_a" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	query, err := packagequery.NewSecurityUpdateEvidence(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_update_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_ten_update_a", Scopes: []string{"report:read"}}}}
	report, err := query.Report(ctx, actor, "prod_ten_update_a", "rel_ten_update_a")
	if err != nil || report.Summary["security_update_subjects"] != 3 || len(report.EvidenceIDs) != 4 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_ten_update_b"
	if _, err := query.Report(ctx, actor, "prod_ten_update_a", "rel_ten_update_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong grant err=%v", err)
	}
	for _, test := range []struct{ tenant, product, release string }{
		{"ten_update_b", "prod_ten_update_a", "rel_ten_update_a"},
		{"ten_update_a", "prod_ten_update_b", "rel_ten_update_a"},
		{"ten_update_a", "prod_ten_update_a", "rel_ten_update_b"},
	} {
		if result, err := store.ReadSecurityUpdateSnapshot(ctx, test.tenant, test.product, test.release); !errors.Is(err, packagequery.ErrSecurityUpdateNotFound) || result.ReleaseID != "" {
			t.Fatalf("unsafe snapshot=%#v err=%v", result, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE remediation_tasks SET evidence_id='ev_scan_b' WHERE id='task_inc_a'`); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadSecurityUpdateSnapshot(ctx, "ten_update_a", "prod_ten_update_a", "rel_ten_update_a"); !errors.Is(err, packagequery.ErrSecurityUpdateProjection) || result.ReleaseID != "" {
		t.Fatalf("foreign evidence reference returned report=%#v err=%v", result, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE remediation_tasks SET evidence_id='ev_task_inc_a' WHERE id='task_inc_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO incidents (id,tenant_id,product_id,release_id,title,severity,status,opened_at,schema_version,created_at)
		SELECT 'inc_capacity_' || n,'ten_update_a','prod_ten_update_a','rel_ten_update_a',
		       'bounded incident','high','open',$1,'incident.v1',$1
		FROM generate_series(1,$2::integer) AS n
	`, now, packagequery.MaxSecurityUpdateEntries); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadSecurityUpdateSnapshot(ctx, "ten_update_a", "prod_ten_update_a", "rel_ten_update_a"); !errors.Is(err, packagequery.ErrSecurityUpdateCapacity) || result.ReleaseID != "" {
		t.Fatalf("oversized projection returned partial report=%#v err=%v", result, err)
	}
}

func TestSecurityUpdateQueryIndexesMigrateBothWays(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		for name, columns := range map[string]string{
			"incidents_security_update_order_idx":         "(tenant_id, product_id, release_id, id)",
			"remediation_tasks_security_update_order_idx": "(tenant_id, release_id, id)",
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
		{file: "../../../migrations/20261001000200_security_update_report_indexes.down.sql"},
		{file: "../../../migrations/20261001000200_security_update_report_indexes.up.sql", want: true},
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
