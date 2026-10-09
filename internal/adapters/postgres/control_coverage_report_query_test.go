package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestReadControlCoverageSnapshotScopesFrameworkLinksAndExceptions(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-31 * 24 * time.Hour)
	for _, statement := range []string{
		`INSERT INTO tenants (id,name) VALUES ('ten_report','Report'),('ten_other','Other')`,
		`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_report','ten_report','Report','report'),('prod_other','ten_other','Other','other')`,
		`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel_report','ten_report','prod_report','1','draft'),('rel_other','ten_other','prod_other','1','draft')`,
		`INSERT INTO control_frameworks (id,tenant_id,name,slug,version,status,schema_version) VALUES ('fw_report','ten_report','Framework','a-framework','1','active','control-framework.v1.0.0'),('fw_other','ten_other','Other','other','1','active','control-framework.v1.0.0')`,
		`INSERT INTO security_controls (id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version) VALUES ('ctrl_report','ten_report','fw_report','C1','Control','Objective','[{"type":"sbom","required":true,"freshness_days":30}]','[]','[]','security-control.v1.0.0'),('ctrl_other','ten_other','fw_other','C1','Other','Objective','[]','[]','[]','security-control.v1.0.0')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, evidence := range []struct{ id, tenant, product, release string }{{"ev_report", "ten_report", "prod_report", "rel_report"}, {"ev_other", "ten_other", "prod_other", "rel_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ($1,$2,$3,$4,'document',$1,'test',$5,'evidence-item.v1','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, evidence.id, evidence.tenant, evidence.product, evidence.release, stale); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO sboms (id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components,created_at) VALUES ('sbom_report','ten_report','ev_report','rel_report','cyclonedx','1.6',0,'[]',$1),('sbom_other','ten_other','ev_other','rel_other','cyclonedx','1.6',0,'[]',$1)`, stale); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ id, subject, product, release string }{{"link_valid", "sbom_report", "prod_report", "rel_report"}, {"link_foreign", "sbom_other", "prod_report", "rel_report"}, {"link_wrong_scope", "sbom_report", "prod_report", "rel_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id,tenant_id,control_id,evidence_type,subject_type,subject_id,product_id,release_id,confidence,notes,schema_version,created_at) VALUES ($1,'ten_report','ctrl_report','sbom','sbom',$2,$3,$4,'high','private note','control-evidence.v1.0.0',$5)`, link.id, link.subject, link.product, link.release, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, exception := range []struct{ id, tenant, release string }{{"ex_valid", "ten_report", "rel_report"}, {"ex_foreign", "ten_other", "rel_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at,approved,control_id,created_at) VALUES ($1,$2,$3,'reviewed','reviewer',$4,true,'ctrl_report',$5)`, exception.id, exception.tenant, exception.release, now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "", "prod_report", "rel_report", now)
	if err != nil || snapshot.FrameworkID != "fw_report" || snapshot.ScopeProductID != "prod_report" || snapshot.ScopeReleaseID != "rel_report" || len(snapshot.Controls) != 1 || len(snapshot.Controls[0].EvidenceRequirements) != 1 || snapshot.Controls[0].EvidenceRequirements[0].FreshnessDays != 30 || len(snapshot.Links) != 1 || snapshot.Links[0].Link.ID != "link_valid" || !snapshot.Links[0].SubjectObservedAt.Equal(stale) || len(snapshot.Exceptions) != 1 || snapshot.Exceptions[0].ID != "ex_valid" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	tenantWide, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "", "", "", now)
	if err != nil || tenantWide.ScopeProductID != "" || len(tenantWide.Exceptions) != 1 || tenantWide.Exceptions[0].ID != "ex_valid" {
		t.Fatalf("tenant-wide snapshot=%#v err=%v", tenantWide, err)
	}
	service, err := packagequery.NewControlCoverageReport(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_report", UserID: "usr_report", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_report", Scopes: []string{"report:read"}}}}
	report, err := service.Coverage(ctx, actor, packagequery.ControlCoverageFilter{ReleaseID: "rel_report"})
	if err != nil || len(report.Controls) != 1 || report.Controls[0].Status != "waived" {
		t.Fatalf("release-granted report=%#v err=%v", report, err)
	}
	if _, err := service.Coverage(ctx, actor, packagequery.ControlCoverageFilter{}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("release grant reached tenant-wide report: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE exceptions SET approved=false WHERE id='ex_valid'`); err != nil {
		t.Fatal(err)
	}
	report, err = service.Coverage(ctx, actor, packagequery.ControlCoverageFilter{ReleaseID: "rel_report"})
	if err != nil || len(report.Controls) != 1 || report.Controls[0].Status != "partial" || len(report.Controls[0].Missing) != 1 || report.Controls[0].Missing[0] != "fresh_sbom" {
		t.Fatalf("stale-subject report=%#v err=%v", report, err)
	}
	for _, coordinates := range []struct{ tenant, framework, product, release string }{
		{"ten_report", "fw_other", "prod_report", "rel_report"},
		{"ten_other", "fw_report", "prod_report", "rel_report"},
		{"ten_report", "fw_report", "prod_other", "rel_report"},
		{"ten_report", "fw_report", "prod_report", "rel_other"},
	} {
		if result, err := store.ReadControlCoverageSnapshot(ctx, coordinates.tenant, coordinates.framework, coordinates.product, coordinates.release, now); !errors.Is(err, packagequery.ErrControlCoverageNotFound) || result.FrameworkID != "" {
			t.Fatalf("unsafe snapshot=%#v err=%v", result, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE exceptions SET approved=true WHERE id='ex_valid'`); err != nil {
		t.Fatal(err)
	}
	for _, oversized := range []struct{ statement, restore string }{
		{`UPDATE control_evidence SET notes=repeat('n',9000) WHERE id='link_valid'`, `UPDATE control_evidence SET notes='private note' WHERE id='link_valid'`},
		{`UPDATE security_controls SET objective=repeat('o',70000) WHERE id='ctrl_report'`, `UPDATE security_controls SET objective='Objective' WHERE id='ctrl_report'`},
		{`UPDATE exceptions SET reason=repeat('r',9000) WHERE id='ex_valid'`, `UPDATE exceptions SET reason='reviewed' WHERE id='ex_valid'`},
	} {
		if _, err := store.pool.Exec(ctx, oversized.statement); err != nil {
			t.Fatal(err)
		}
		if result, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "fw_report", "prod_report", "rel_report", now); !errors.Is(err, packagequery.ErrControlCoverageCapacity) || result.FrameworkID != "" {
			t.Fatalf("oversized report input returned %d controls, %d links, %d exceptions; err=%v", len(result.Controls), len(result.Links), len(result.Exceptions), err)
		}
		if _, err := store.pool.Exec(ctx, oversized.restore); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE security_controls SET evidence_requirements='{}'::jsonb WHERE id='ctrl_report'`); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "fw_report", "prod_report", "rel_report", now); !errors.Is(err, packagequery.ErrControlCoverageProjection) || result.FrameworkID != "" {
		t.Fatalf("invalid stored requirements snapshot=%#v err=%v", result, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE security_controls SET evidence_requirements='[]'::jsonb WHERE id='ctrl_report'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO security_controls (id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)
		SELECT 'ctrl_byte_' || n,'ten_report','fw_report','byte_' || n,'Control',repeat('b',20000),'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'security-control.v1.0.0'
		FROM generate_series(1,500) AS n`); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "fw_report", "prod_report", "rel_report", now); !errors.Is(err, packagequery.ErrControlCoverageCapacity) || result.FrameworkID != "" {
		t.Fatalf("aggregate bytes returned %d controls; err=%v", len(result.Controls), err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM security_controls WHERE tenant_id='ten_report' AND framework_id='fw_report' AND id LIKE 'ctrl_byte_%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO security_controls (id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)
		SELECT 'ctrl_capacity_' || n,'ten_report','fw_report','capacity_' || n,'Control','Objective','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'security-control.v1.0.0'
		FROM generate_series(1,$1::integer) AS n`, packagequery.MaxControlCoverageEntries); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ReadControlCoverageSnapshot(ctx, "ten_report", "fw_report", "prod_report", "rel_report", now); !errors.Is(err, packagequery.ErrControlCoverageCapacity) || result.FrameworkID != "" {
		t.Fatalf("oversized snapshot=%#v err=%v", result, err)
	}
}
