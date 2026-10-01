package postgres

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestPostgresControlEvidencePagesCurrentSubjectsBeforeGrantLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_links", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_frameworks (id, tenant_id, name, slug, version, status, schema_version, created_at) VALUES ($1, $2, $1, $1, '1', 'active', 'control-framework.v1.0.0', $3)`, "fw_"+tenant, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO security_controls (id, tenant_id, framework_id, code, title, objective, evidence_requirements, applicability, limitations, schema_version, created_at) VALUES ($1, $2, $3, 'C1', $1, $1, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'security-control.v1.0.0', $4)`, "ctrl_"+tenant, tenant, "fw_"+tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_links"}, {"prod_b", "ten_links"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, tenant, product, release string }{{"ev_a", "ten_links", "prod_a", "rel_prod_a"}, {"ev_b", "ten_links", "prod_b", "rel_prod_b"}, {"ev_other", "ten_other", "prod_other", "rel_prod_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, 'document', $1, 'test', $5, 'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical', 'canonical-json.v1', 'L2', 'pending', $5)`, item.id, item.tenant, item.product, item.release, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ id, tenant, control, subject, product, release string }{
		{"a_valid", "ten_links", "ctrl_ten_links", "ev_a", "prod_a", "rel_prod_a"},
		{"b_valid", "ten_links", "ctrl_ten_links", "ev_b", "prod_b", "rel_prod_b"},
		{"c_foreign_subject", "ten_links", "ctrl_ten_links", "ev_other", "prod_a", "rel_prod_a"},
		{"d_wrong_parent", "ten_links", "ctrl_ten_links", "ev_a", "prod_a", "rel_prod_b"},
		{"e_foreign_control", "ten_links", "ctrl_ten_other", "ev_a", "prod_a", "rel_prod_a"},
		{"f_missing_subject", "ten_links", "ctrl_ten_links", "ev_missing", "prod_a", "rel_prod_a"},
		{"g_foreign_tenant", "ten_other", "ctrl_ten_other", "ev_other", "prod_other", "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id, tenant_id, control_id, evidence_type, subject_type, subject_id, product_id, release_id, confidence, notes, schema_version, created_at) VALUES ($1, $2, $3, 'artifact', 'evidence', $4, $5, $6, 'high', 'private note', 'control-evidence.v1.0.0', $7)`, link.id, link.tenant, link.control, link.subject, link.product, link.release, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := riskquery.NewControlEvidence(store)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_links", UserID: "usr_1", Scopes: []string{"controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"controls:read"}}}}
	result, err := service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "b_valid" || result.Next != nil {
		t.Fatalf("product page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_a", Scopes: []string{"controls:read"}}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "a_valid" {
		t.Fatalf("release page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"controls:read"}}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "a_valid" || result.Next == nil {
		t.Fatalf("first tenant page=%#v error=%v", result, err)
	}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, result.Next)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "b_valid" || result.Next != nil {
		t.Fatalf("second tenant page=%#v error=%v", result, err)
	}
	page.Sort, page.Direction = appquery.SortCreatedAt, appquery.Descending
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{ControlID: "ctrl_ten_links"}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "b_valid" || result.Next == nil {
		t.Fatalf("descending created-at page=%#v error=%v", result, err)
	}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{ControlID: "ctrl_ten_links"}, page, result.Next)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "a_valid" || result.Next != nil {
		t.Fatalf("descending created-at continuation=%#v error=%v", result, err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ('art_a', 'ten_links', 'artifact', 'application/octet-stream', 4, 'sha256:artifact', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET subject_refs = '[{"type":"artifact","id":"art_a"}]'::jsonb WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id, tenant_id, control_id, evidence_type, subject_type, subject_id, product_id, release_id, confidence, schema_version, created_at) VALUES ('h_artifact', 'ten_links', 'ctrl_ten_links', 'artifact', 'artifact', 'art_a', 'prod_a', 'rel_prod_a', 'high', 'control-evidence.v1.0.0', $1)`, now); err != nil {
		t.Fatal(err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"controls:read"}}
	page.PageSize = 10
	page.Sort, page.Direction = appquery.SortID, appquery.Ascending
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != 2 || result.Items[0].ID != "a_valid" || result.Items[1].ID != "h_artifact" {
		t.Fatalf("artifact-associated product page=%#v error=%v", result, err)
	}
}

func TestPostgresControlEvidencePageUsesSubjectTime(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	observed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	linked := observed.Add(60 * 24 * time.Hour)
	for _, statement := range []string{
		`INSERT INTO tenants (id,name) VALUES ('ten_time','Time')`,
		`INSERT INTO control_frameworks (id,tenant_id,name,slug,version,status,schema_version) VALUES ('fw_time','ten_time','Framework','framework','1','active','control-framework.v1.0.0')`,
		`INSERT INTO security_controls (id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version) VALUES ('ctrl_time','ten_time','fw_time','C1','Control','Objective','[]','[]','[]','security-control.v1.0.0')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_time','ten_time','document','Evidence','test',$1,'evidence-item.v1','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id,tenant_id,control_id,evidence_type,subject_type,subject_id,confidence,schema_version,created_at) VALUES ('link_time','ten_time','ctrl_time','artifact','evidence','ev_time','high','control-evidence.v1.0.0',$1)`, linked); err != nil {
		t.Fatal(err)
	}
	result, err := store.PageControlEvidence(ctx, riskquery.ControlEvidencePageRequest{TenantID: "ten_time", TenantWide: true, Page: appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}})
	if err != nil || len(result.Items) != 1 || !result.Items[0].ObservedAt.Equal(observed) {
		t.Fatalf("subject time page=%#v err=%v", result, err)
	}
}

func TestPostgresControlEvidenceQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN ('control_evidence_tenant_created_id_idx', 'control_evidence_tenant_id_idx', 'evidence_items_subject_refs_gin_idx', 'vulnerability_scans_findings_gin_idx', 'build_runs_outputs_gin_idx')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		indexes := map[string]string{}
		for rows.Next() {
			var name, definition string
			if err := rows.Scan(&name, &definition); err != nil {
				t.Fatal(err)
			}
			indexes[name] = definition
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for name, columns := range map[string]string{
			"control_evidence_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"control_evidence_tenant_id_idx":         "(tenant_id, id)",
			"evidence_items_subject_refs_gin_idx":    "USING gin (subject_refs)",
			"vulnerability_scans_findings_gin_idx":   "USING gin (findings)",
			"build_runs_outputs_gin_idx":             "USING gin (outputs)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing control evidence index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained control evidence index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260929000300_control_evidence_list_indexes.down.sql"},
		{file: "../../../migrations/20260929000300_control_evidence_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run control evidence index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

func TestPostgresControlEvidencePagesSupportedSubjectTypes(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	fixtures := []string{
		`INSERT INTO tenants (id,name) VALUES ('ten_subjects','Subjects')`,
		`INSERT INTO control_frameworks (id,tenant_id,name,slug,version,status,schema_version) VALUES ('fw','ten_subjects','Framework','framework','1','active','control-framework.v1.0.0')`,
		`INSERT INTO security_controls (id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version) VALUES ('ctrl','ten_subjects','fw','C1','Control','Objective','[]','[]','[]','security-control.v1.0.0')`,
		`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod','ten_subjects','Product','product')`,
		`INSERT INTO projects (id,tenant_id,product_id,name) VALUES ('proj','ten_subjects','prod','Project')`,
		`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel','ten_subjects','prod','1','draft')`,
		`INSERT INTO evidence_items (id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev','ten_subjects','prod','proj','rel','document','Evidence','test',now(),'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`,
		`INSERT INTO artifacts (id,tenant_id,name,media_type,size,digest) VALUES ('art','ten_subjects','Artifact','application/octet-stream',1,'sha256:artifact')`,
		`UPDATE evidence_items SET subject_refs = '[{"type":"artifact","id":"art"}]' WHERE id = 'ev'`,
		`INSERT INTO sboms (id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES ('sbom','ten_subjects','ev','rel','cyclonedx','1.6',0,'[]')`,
		`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings) VALUES ('scan','ten_subjects','ev','rel','test','rel','{}','[{"id":"finding"}]')`,
		`INSERT INTO vex_documents (id,tenant_id,evidence_id,release_id,format,author,statement_count,status_summary,schema_version) VALUES ('vex','ten_subjects','ev','rel','openvex','test',0,'{}','vex.v1.0.0')`,
		`INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version) VALUES ('decision','ten_subjects','finding','scan','rel','CVE-1','affected','test','manual','vulnerability-decision.v1.0.0')`,
		`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at) VALUES ('exception','ten_subjects','rel','test','test',now() + interval '1 day')`,
		`INSERT INTO build_runs (id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version) VALUES ('build','ten_subjects','proj','rel','test','abc','completed',now(),'[{"artifact_id":"art","digest":"sha256:artifact"}]','build-run.v1.0.0')`,
		`INSERT INTO build_attestations (id,tenant_id,build_id,evidence_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES ('attestation','ten_subjects','build','ev','sha256:attestation',1,'application/json','test','[]',0,0,'pending','build-attestation.v1.0.0')`,
		`INSERT INTO openapi_contracts (id,tenant_id,product_id,release_id,version,hash,path_count,evidence_id) VALUES ('contract','ten_subjects','prod','rel','1','sha256:contract',0,'ev')`,
		`INSERT INTO release_bundles (id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES ('bundle','ten_subjects','rel','draft','{}','sha256:bundle','[]')`,
	}
	for _, statement := range fixtures {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("fixture %s: %v", statement, err)
		}
	}
	types := []struct{ kind, subject, product, release string }{
		{"evidence", "ev", "prod", "rel"}, {"evidence_item", "ev", "prod", "rel"},
		{"product", "prod", "prod", ""}, {"release", "rel", "prod", "rel"},
		{"artifact", "art", "prod", "rel"}, {"sbom", "sbom", "prod", "rel"},
		{"vulnerability_scan", "scan", "prod", "rel"}, {"vex", "vex", "prod", "rel"},
		{"vulnerability_decision", "decision", "prod", "rel"}, {"finding", "finding", "prod", "rel"},
		{"vulnerability_finding", "finding", "prod", "rel"}, {"exception", "exception", "prod", "rel"},
		{"build", "build", "prod", "rel"}, {"build_attestation", "attestation", "prod", "rel"},
		{"openapi_contract", "contract", "prod", "rel"}, {"release_bundle", "bundle", "prod", "rel"},
	}
	for _, subject := range types {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id,tenant_id,control_id,evidence_type,subject_type,subject_id,product_id,release_id,confidence,schema_version) VALUES ($1,'ten_subjects','ctrl','artifact',$2,$3,$4,NULLIF($5,''),'high','control-evidence.v1.0.0')`, "link_"+subject.kind, subject.kind, subject.subject, subject.product, subject.release); err != nil {
			t.Fatalf("link %s: %v", subject.kind, err)
		}
	}
	service, err := riskquery.NewControlEvidence(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_subjects", UserID: "user", Scopes: []string{"controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod", Scopes: []string{"controls:read"}}}}
	page := appquery.PageRequest{PageSize: 100, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		got = append(got, item.SubjectType)
	}
	sort.Strings(got)
	want := make([]string, 0, len(types))
	for _, subject := range types {
		want = append(want, subject.kind)
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("subject types got=%v want=%v", got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("subject types got=%v want=%v", got, want)
		}
	}
	for _, statement := range []string{
		`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_wrong','ten_subjects','Other','other')`,
		`INSERT INTO projects (id,tenant_id,product_id,name) VALUES ('proj_wrong','ten_subjects','prod_wrong','Other')`,
		`INSERT INTO evidence_items (id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_bad','ten_subjects','prod','proj_wrong','rel','document','Broken','test',now(),'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`,
		`INSERT INTO sboms (id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES ('sbom_bad','ten_subjects','ev_bad','rel','cyclonedx','1.6',0,'[]')`,
		`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings) VALUES ('scan_bad','ten_subjects','ev_bad','rel','test','rel','{}','[{"id":"finding_bad"}]')`,
		`INSERT INTO vex_documents (id,tenant_id,evidence_id,release_id,format,author,statement_count,status_summary,schema_version) VALUES ('vex_bad','ten_subjects','ev_bad','rel','openvex','test',0,'{}','vex.v1.0.0')`,
		`INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version) VALUES ('decision_bad','ten_subjects','finding_bad','scan_bad','rel','CVE-2','affected','test','manual','vulnerability-decision.v1.0.0')`,
		`INSERT INTO openapi_contracts (id,tenant_id,product_id,release_id,version,hash,path_count,evidence_id) VALUES ('contract_bad','ten_subjects','prod','rel','1','sha256:bad',0,'ev_bad')`,
		`INSERT INTO build_attestations (id,tenant_id,build_id,evidence_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES ('attestation_bad','ten_subjects','build','ev_bad','sha256:bad',1,'application/json','test','[]',0,0,'pending','build-attestation.v1.0.0')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("broken fixture %s: %v", statement, err)
		}
	}
	for _, subject := range []struct{ kind, id string }{{"sbom", "sbom_bad"}, {"vulnerability_scan", "scan_bad"}, {"vex", "vex_bad"}, {"vulnerability_decision", "decision_bad"}, {"finding", "finding_bad"}, {"openapi_contract", "contract_bad"}, {"build_attestation", "attestation_bad"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id,tenant_id,control_id,evidence_type,subject_type,subject_id,product_id,release_id,confidence,schema_version) VALUES ($1,'ten_subjects','ctrl','artifact',$2,$3,'prod','rel','high','control-evidence.v1.0.0')`, "broken_"+subject.kind, subject.kind, subject.id); err != nil {
			t.Fatal(err)
		}
	}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != len(types) {
		t.Fatalf("broken parent links leaked: got=%d want=%d error=%v", len(result.Items), len(types), err)
	}
	for _, statement := range []string{
		`INSERT INTO tenants (id,name) VALUES ('ten_foreign','Foreign')`,
		`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_foreign','ten_foreign','Foreign','foreign')`,
		`INSERT INTO projects (id,tenant_id,product_id,name) VALUES ('proj_foreign_parent','ten_subjects','prod_foreign','Broken')`,
		`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel_foreign_parent','ten_subjects','prod_foreign','2','draft')`,
		`INSERT INTO evidence_items (id,tenant_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_foreign_parent','ten_subjects','proj_foreign_parent','rel_foreign_parent','document','Broken','test',now(),'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`,
		`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at) VALUES ('exception_foreign_parent','ten_subjects','rel_foreign_parent','test','test',now() + interval '1 day')`,
		`INSERT INTO release_bundles (id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES ('bundle_foreign_parent','ten_subjects','rel_foreign_parent','draft','{}','sha256:bad','[]')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("cross-tenant parent fixture %s: %v", statement, err)
		}
	}
	for _, subject := range []struct{ kind, id string }{{"evidence", "ev_foreign_parent"}, {"release", "rel_foreign_parent"}, {"exception", "exception_foreign_parent"}, {"release_bundle", "bundle_foreign_parent"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO control_evidence (id,tenant_id,control_id,evidence_type,subject_type,subject_id,confidence,schema_version) VALUES ($1,'ten_subjects','ctrl','artifact',$2,$3,'high','control-evidence.v1.0.0')`, "foreign_"+subject.kind, subject.kind, subject.id); err != nil {
			t.Fatal(err)
		}
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"controls:read"}}
	result, err = service.ListPage(ctx, actor, riskquery.ControlEvidenceFilter{}, page, nil)
	if err != nil || len(result.Items) != len(types) {
		t.Fatalf("cross-tenant parent links leaked: got=%d want=%d error=%v", len(result.Items), len(types), err)
	}
}
