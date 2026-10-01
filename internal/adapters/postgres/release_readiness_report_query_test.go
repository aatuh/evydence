package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestReadReleaseReadinessReportSnapshotIsScopedBoundedAndReadOnly(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants (id,name) VALUES ('ten_report','Report'),('ten_foreign','Foreign')`)
	exec(`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_report','ten_report','Report','report'),('prod_foreign','ten_foreign','Foreign','foreign')`)
	exec(`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel_report','ten_report','prod_report','1','draft'),('rel_foreign','ten_foreign','prod_foreign','1','draft')`)
	exec(`INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		VALUES ('ev_report','ten_report','prod_report','rel_report','vulnerability_scan','Report','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending')`, now)
	exec(`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings)
		VALUES ('scan_report','ten_report','ev_report','rel_report','test','target','{}','[{"id":"critical_open","vulnerability":"CVE-1","component":"pkg:one","severity":"critical","state":"open"},{"id":"critical_fixed","severity":"critical"},{"id":"critical_waived","severity":"critical"},{"id":"high_open","severity":"high"}]')`)
	exec(`INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version,internal_notes)
		VALUES ('decision_report','ten_report','critical_fixed','scan_report','rel_report','CVE-fixed','fixed','patched','manual','decision.v1','private-notes-marker')`)
	exec(`INSERT INTO exceptions (id,tenant_id,release_id,finding_id,reason,owner,expires_at,approved,approved_by,approved_at)
		VALUES ('exc_report','ten_report','rel_report','critical_waived','reviewed risk','owner',$1,true,'approver',$3),('exc_expired','ten_report','rel_report','critical_open','expired','owner',$2,true,'approver',$3),('exc_pending','ten_report','rel_report','critical_open','pending','owner',$1,false,NULL,NULL)`, now.Add(time.Hour), now, now)
	exec(`INSERT INTO redaction_profiles (id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)
		VALUES ('profile_report','ten_report','Review',ARRAY['sbom'],ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'],'redaction.v1',$1)`, now)
	exec(`INSERT INTO customer_security_packages (id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)
		VALUES ('package_report','ten_report','prod_report','rel_report','profile_report','Report','generated','{}','hash',$1,'package.v1',$2)`, now.Add(time.Hour), now)
	if _, err := store.ReadReleaseReadinessReportSnapshot(ctx, "ten_report", "rel_foreign", now); !errors.Is(err, packagequery.ErrReleaseReadinessNotFound) {
		t.Fatal(err)
	}
	snapshot, err := store.ReadReleaseReadinessReportSnapshot(ctx, "ten_report", "rel_report", now)
	if err != nil || len(snapshot.BlockingFindings) != 1 || snapshot.BlockingFindings[0].FindingID != "critical_open" || len(snapshot.AcceptedExceptions) != 1 || snapshot.AcceptedExceptions[0].ID != "exc_report" || snapshot.ActiveDecisionCount != 1 || !snapshot.HasActiveCustomerPackage || !snapshot.Readiness.UnhandledCritical || !snapshot.Readiness.UnhandledHigh {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	service, err := packagequery.NewReleaseReadinessReport(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_report", UserID: "user_report", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_report", Scopes: []string{"verify:read"}}}}
	var before, after int
	count := `SELECT (SELECT count(*) FROM policy_evaluations)+(SELECT count(*) FROM audit_chain_entries)`
	if err := store.pool.QueryRow(ctx, count).Scan(&before); err != nil {
		t.Fatal(err)
	}
	report, err := service.Report(ctx, actor, "rel_report")
	if err != nil || report.Result != "failed" || len(report.BlockingFindings) != 1 || report.AcceptedExceptions[0].Reason != "reviewed risk" || len(report.Sections) != 5 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if err := store.pool.QueryRow(ctx, count).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("read-only report wrote state")
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), "private-notes-marker") {
		t.Fatalf("private projection leak err=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_foreign"
	if _, err := service.Report(ctx, actor, "rel_report"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sql string
		args      []any
	}{
		{"oversized finding", `UPDATE vulnerability_scans SET findings=$1 WHERE id='scan_report'`, []any{`[{"id":"critical_open","severity":"critical","vulnerability":"` + strings.Repeat("x", 1100) + `"}]`}},
		{"malformed findings", `UPDATE vulnerability_scans SET findings='{}' WHERE id='scan_report'`, nil},
		{"oversized exception", `UPDATE vulnerability_scans SET findings='[]'; UPDATE exceptions SET reason=repeat('x',5000) WHERE id='exc_report'`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.sql, tc.args...)
			result, err := store.ReadReleaseReadinessReportSnapshot(ctx, "ten_report", "rel_report", now)
			if !errors.Is(err, packagequery.ErrReleaseReadinessProjection) || result.Readiness.TenantID != "" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
	exec(`UPDATE exceptions SET reason='reviewed' WHERE id='exc_report'`)
	exec(`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at,approved,approved_by,approved_at) SELECT 'exc_capacity_'||n,'ten_report','rel_report','risk','owner',$1,true,'approver',$2 FROM generate_series(1,$3) n`, now.Add(time.Hour), now, packagequery.MaxReleaseReadinessEntries)
	if _, err := store.ReadReleaseReadinessReportSnapshot(ctx, "ten_report", "rel_report", now); !errors.Is(err, packagequery.ErrReleaseReadinessProjection) {
		t.Fatalf("capacity err=%v", err)
	}
}
