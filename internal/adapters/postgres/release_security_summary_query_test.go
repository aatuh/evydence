package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestReadReleaseSecuritySummarySnapshotUsesOneScopedView(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants (id,name) VALUES ('ten_summary','Summary'),('ten_foreign','Foreign')`)
	exec(`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_summary','ten_summary','Summary product','summary'),('prod_foreign','ten_foreign','Foreign','foreign')`)
	exec(`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel_summary','ten_summary','prod_summary','1.2.3','draft'),('rel_foreign','ten_foreign','prod_foreign','1','draft')`)
	for _, evidence := range []struct{ id, typ string }{{"ev_sbom", "sbom"}, {"ev_scan", "vulnerability_scan"}} {
		exec(`INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
			VALUES ($1,'ten_summary','prod_summary','rel_summary',$2,'Summary fixture','test',$3,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending')`, evidence.id, evidence.typ, now)
	}
	exec(`INSERT INTO sboms (id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES ('sbom_summary','ten_summary','ev_sbom','rel_summary','cyclonedx','1.6',0,'[]')`)
	exec(`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings)
		VALUES ('scan_summary','ten_summary','ev_scan','rel_summary','test','target','{}','[{"id":"finding_critical","vulnerability":"CVE-1","component":"pkg:critical","severity":"critical","state":"open"},{"id":"finding_high","vulnerability":"CVE-2","component":"pkg:high","severity":"high","state":"open"}]')`)
	exec(`INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,component,status,justification,source,schema_version)
		VALUES ('decision_summary','ten_summary','finding_critical','scan_summary','rel_summary','CVE-1','pkg:critical','fixed','patched','manual','decision.v1')`)
	exec(`INSERT INTO approval_records (id,tenant_id,subject_type,subject_id,decision,reason,approver_id,schema_version,created_at)
		VALUES ('approval_yes','ten_summary','release','rel_summary','approved','reviewed','user_a','approval.v1',$1),('approval_no','ten_summary','release','rel_summary','rejected','reviewed','user_b','approval.v1',$1)`, now)
	exec(`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at,approved) VALUES ('exception_pending','ten_summary','rel_summary','review','owner',$1,false),('exception_expired','ten_summary','rel_summary','review','owner',$2,true)`, now.Add(time.Hour), now.Add(-time.Hour))
	if _, err := store.ReadReleaseSecuritySummarySnapshot(ctx, "ten_summary", "rel_foreign"); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatalf("foreign release err=%v", err)
	}
	snapshot, err := store.ReadReleaseSecuritySummarySnapshot(ctx, "ten_summary", "rel_summary")
	if err != nil || snapshot.TenantID != "ten_summary" || snapshot.Product.Name != "Summary product" || snapshot.Release.Version != "1.2.3" || snapshot.Counts["sboms"] != 1 || snapshot.Counts["vulnerability_scans"] != 1 || snapshot.Counts["vulnerability_decisions"] != 1 || snapshot.OpenFindingsBySeverity["critical"] != 1 || snapshot.OpenFindingsBySeverity["high"] != 1 || snapshot.DecisionsByStatus["fixed"] != 1 || len(snapshot.MissingRequiredDecisions) != 1 || snapshot.MissingRequiredDecisions[0].FindingID != "finding_high" || snapshot.ApprovalSummary.Total != 2 || snapshot.ApprovalSummary.Approved != 1 || snapshot.ExceptionSummary.Total != 2 || snapshot.ExceptionSummary.Expired != 1 || snapshot.ExceptionSummary.Unapproved != 1 || !snapshot.Readiness.UnhandledHigh || snapshot.Readiness.UnhandledCritical {
		t.Fatalf("security summary snapshot=%#v err=%v", snapshot, err)
	}
	service, err := riskquery.NewReleaseSecuritySummary(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_summary", UserID: "user_summary", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_summary", Scopes: []string{"report:read"}}}}
	summary, err := service.Summary(ctx, actor, "rel_summary")
	if err != nil || summary.Product.ID != "prod_summary" || summary.Release.ID != "rel_summary" || summary.ReadinessStatus != "failed" || summary.PackageStatus != "not_generated" || len(summary.MissingRequiredDecisions) != 1 {
		t.Fatalf("durable summary=%#v err=%v", summary, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_foreign"
	if _, err := service.Summary(ctx, actor, "rel_summary"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign release grant reached summary: %v", err)
	}
	exec(`UPDATE vulnerability_scans SET findings=$1 WHERE id='scan_summary'`, `[{"id":"finding_high","vulnerability":"`+strings.Repeat("x", 1100)+`","severity":"high","state":"open"}]`)
	if result, err := store.ReadReleaseSecuritySummarySnapshot(ctx, "ten_summary", "rel_summary"); !errors.Is(err, riskquery.ErrInvalidProjection) || result.TenantID != "" {
		t.Fatalf("oversized finding snapshot=%#v err=%v", result, err)
	}
	exec(`UPDATE vulnerability_scans SET findings='{}'::jsonb WHERE id='scan_summary'`)
	if result, err := store.ReadReleaseSecuritySummarySnapshot(ctx, "ten_summary", "rel_summary"); !errors.Is(err, riskquery.ErrInvalidProjection) || result.TenantID != "" {
		t.Fatalf("malformed findings snapshot=%#v err=%v", result, err)
	}
}
