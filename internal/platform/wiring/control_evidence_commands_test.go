package wiring

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func seedControlEvidenceSubjects(t *testing.T, ctx context.Context, store *postgres.Store, pool *pgxpool.Pool) {
	t.Helper()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Controls'),('other','Other')ON CONFLICT(id)DO NOTHING;INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('other-product','other','Other','other');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft');INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('fw','tenant','Framework','framework','1','active','control-framework.v1.0.0');INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)VALUES('control','tenant','fw','C','Control','Objective','[]','[]','[]','security-control.v1.0.0')`)
	if err := app.ExecuteUnitOfWork(ctx, store, candidateReferenceFixture); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE vulnerability_scans SET findings='[{"id":"finding"}]';INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version)VALUES('decision','tenant','finding','scan','release','CVE-TEST','fixed','reviewed','manual','vulnerability-decision.v1.0.0');INSERT INTO exceptions(id,tenant_id,release_id,reason,owner,expires_at)VALUES('exception','tenant','release','reviewed','owner',now()+interval '1 day');INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-attestation","type":"build_attestation","project_id":"project"}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version)VALUES('attestation','tenant','build','ev-attestation','sha256:payload',1,'application/json','test','[]',0,0,'pending','build-attestation.v1.0.0')`)
}

func TestPostgresControlEvidenceCommandsLinkEverySubjectWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildControlEvidenceCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:write"}}}}
	subjects := []struct{ typ, id string }{{"evidence", "ev-sbom"}, {"evidence_item", "ev-sbom"}, {"product", "product"}, {"release", "release"}, {"artifact", "artifact"}, {"sbom", "sbom"}, {"vulnerability_scan", "scan"}, {"vex", "vex"}, {"vulnerability_decision", "decision"}, {"finding", "finding"}, {"vulnerability_finding", "finding"}, {"exception", "exception"}, {"build", "build"}, {"build_attestation", "attestation"}, {"openapi_contract", "contract"}, {"release_bundle", "bundle"}}
	created := map[string]riskdomain.ControlEvidence{}
	for _, subject := range subjects {
		in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: subject.typ, SubjectID: subject.id, Confidence: "high", Notes: "reviewed", ProductID: "product"}
		v, err := commands.LinkControlEvidence(ctx, actor, "control", in)
		if err != nil || v.SubjectType != subject.typ || v.SubjectID != subject.id || v.ProductID != "product" || v.ReleaseID != "" || v.Notes != "reviewed" || v.Confidence != "high" || v.SchemaVersion != riskdomain.ControlEvidenceSchemaVersion {
			t.Fatal("subject failed", subject, v, err)
		}
		created[v.ID] = v
		in.Confidence = "low"
		in.Notes = "changed"
		duplicate, err := commands.LinkControlEvidence(ctx, actor, "control", in)
		if err != nil || duplicate != v {
			t.Fatal("duplicate changed", subject, duplicate, err)
		}
		bad := in
		bad.ProductID = "other-product"
		if v, err := commands.LinkControlEvidence(ctx, actor, "control", bad); !errors.Is(err, riskapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign claimed scope accepted", subject, v.ID, err)
		}
		bad.SubjectID = "missing"
		if v, err := commands.LinkControlEvidence(ctx, actor, "control", bad); !errors.Is(err, riskapp.ErrNotFound) || v.ID != "" {
			t.Fatal("missing subject accepted", subject, v.ID, err)
		}
	}
	var links, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='control_evidence.linked' AND actor_type='human_user' AND actor_id='human')`).Scan(&links, &audits); err != nil || links != len(subjects) || audits != len(subjects) {
		t.Fatal("link/audit count changed", links, audits, err)
	}
	query, err := BuildControlEvidenceQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	reader := actor
	reader.Scopes = []string{"controls:read"}
	reader.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:read"}}}
	page, err := query.ListPage(ctx, reader, riskquery.ControlEvidenceFilter{ControlID: "control"}, appquery.PageRequest{PageSize: 100, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(page.Items) != len(subjects) || page.Next != nil {
		t.Fatal("focused read did not see all committed links", len(page.Items), err)
	}
	for _, v := range page.Items {
		v.CreatedAt = v.CreatedAt.UTC()
		if v != created[v.ID] {
			t.Fatal("stored link projection changed", v.ID)
		}
	}
	actor.ResourceGrants = nil
	if v, err := commands.LinkControlEvidence(ctx, actor, "control", riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom", Confidence: "high", ProductID: "product"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("removed grant disclosed duplicate", v.ID, err)
	}
}

func TestPostgresControlEvidenceCommandsRollbackAndSerializeDuplicateLinks(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Controls');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product');INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('fw','tenant','Framework','framework','1','active','control-framework.v1.0.0');INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)VALUES('control','tenant','fw','C','Control','Objective','[]','[]','[]','security-control.v1.0.0')`); err != nil {
		t.Fatal(err)
	}
	one, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:write"}}
	in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high", Notes: "reviewed"}
	counts := func(want int) {
		t.Helper()
		var l, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries)`).Scan(&l, &a); err != nil || l != want || a != want {
			t.Fatal("effects changed", l, a, err)
		}
	}
	for _, table := range []string{"control_evidence", "audit_chain_entries"} {
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_control_link()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private link SQL';END$$;CREATE TRIGGER reject_control_link BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_control_link()`); err != nil {
			t.Fatal(err)
		}
		if v, err := one.LinkControlEvidence(ctx, actor, "control", in); err == nil || v.ID != "" {
			t.Fatal("storage failure accepted", v.ID, err)
		} else if problem := app.DescribeProblem(err); problem.Code != app.CodeInternalError || strings.Contains(fmt.Sprint(problem), "private link SQL") {
			t.Fatal("storage failure not mapped to safe problem", problem)
		}
		counts(0)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_control_link ON `+table+`;DROP FUNCTION reject_control_link()`); err != nil {
			t.Fatal(err)
		}
	}
	rollback := errors.New("outer rollback")
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, actor, "POST", "/v1/security-controls/control/evidence", "rollback", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		if _, err := one.LinkControlEvidence(ctx, actor, "control", in); err != nil {
			return 0, nil, err
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("outer transaction not used", err)
	}
	counts(0)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan riskdomain.ControlEvidence, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			cmd := one
			if i%2 == 1 {
				cmd = two
			}
			v, err := cmd.LinkControlEvidence(ctx, actor, "control", in)
			results <- v
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("duplicate contender failed", err)
		}
	}
	var original riskdomain.ControlEvidence
	for v := range results {
		if original.ID == "" {
			original = v
		}
		if !reflect.DeepEqual(v, original) {
			t.Fatal("contenders returned different links", v, original)
		}
	}
	counts(1)
	getter := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	callback := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		runs++
		v, err := one.LinkControlEvidence(ctx, actor, "control", in)
		return 201, v, err
	}
	status, response, err := getter.WithBody(ctx, actor, "POST", "/v1/security-controls/control/evidence", "replay", []byte(`{"subject":"product"}`), callback)
	if err != nil || status != 201 || response.(riskdomain.ControlEvidence) != original {
		t.Fatal("idempotent link response changed", status, err)
	}
	if _, _, err := getter.WithBody(ctx, actor, "POST", "/v1/security-controls/control/evidence", "replay", []byte(`{"subject":"product"}`), callback); err != nil || runs != 1 {
		t.Fatal("replay reexecuted link", runs, err)
	}
	if _, _, err := getter.WithBody(ctx, actor, "POST", "/v1/security-controls/control/evidence", "replay", []byte(`{"subject":"changed"}`), callback); !errors.Is(err, app.ErrIdempotencyConflict) || runs != 1 {
		t.Fatal("changed replay accepted", runs, err)
	}
	counts(1)
	if _, err := pool.Exec(ctx, `UPDATE control_evidence SET notes=repeat('x',9000000)`); err != nil {
		t.Fatal(err)
	}
	if v, err := one.LinkControlEvidence(ctx, actor, "control", in); !errors.Is(err, riskapp.ErrValidation) || v.ID != "" {
		t.Fatal("oversized duplicate returned", v.ID, err)
	}
	counts(1)
}

func TestPostgresControlEvidenceCommandsRejectForeignSubjectsAndBrokenSourceRelationships(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('other-project','other','other-product','Other');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('other-release','other','other-product','1','draft'),('wrong-release','tenant','product','2','draft');INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('other-fw','other','Other','other','1','active','control-framework.v1.0.0')`)
	for _, id := range []string{"ev-sbom", "ev-scan", "ev-vex", "ev-contract", "ev-attestation"} {
		exec(`INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||jsonb_build_object('id',$1::text,'tenant_id','other','product_id','other-product','project_id','other-project','release_id','other-release'))).* FROM evidence_items e WHERE e.id=$2`, "other-"+id, id)
	}
	rows := []struct{ table, typ, id string }{{"artifacts", "artifact", "artifact"}, {"build_runs", "build", "build"}, {"sboms", "sbom", "sbom"}, {"vulnerability_scans", "vulnerability_scan", "scan"}, {"vex_documents", "vex", "vex"}, {"vulnerability_decisions", "vulnerability_decision", "decision"}, {"exceptions", "exception", "exception"}, {"build_attestations", "build_attestation", "attestation"}, {"openapi_contracts", "openapi_contract", "contract"}, {"release_bundles", "release_bundle", "bundle"}}
	for _, row := range rows {
		exec(fmt.Sprintf(`INSERT INTO %s SELECT(jsonb_populate_record(NULL::%s,to_jsonb(x)||jsonb_build_object('id',$1::text,'tenant_id','other','product_id','other-product','project_id','other-project','release_id','other-release','evidence_id','other-'||(to_jsonb(x)->>'evidence_id'),'scan_id','other-scan','finding_id','other-finding','build_id','other-build','findings','[{"id":"other-finding"}]'::jsonb,'digest','sha256:'||repeat('b',64)))).* FROM %s x WHERE x.id=$2`, row.table, row.table, row.table), "other-"+row.id, row.id)
	}
	commands, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:write"}}
	denied := func(typ, id string) {
		t.Helper()
		v, err := commands.LinkControlEvidence(ctx, actor, "control", riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: typ, SubjectID: id, Confidence: "high"})
		if !errors.Is(err, riskapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign or inconsistent subject accepted", typ, id, v.ID, err)
		}
	}
	for _, row := range rows {
		denied(row.typ, "other-"+row.id)
	}
	for _, row := range []struct{ typ, id string }{{"evidence", "other-ev-sbom"}, {"evidence_item", "other-ev-sbom"}, {"product", "other-product"}, {"release", "other-release"}, {"finding", "other-finding"}, {"vulnerability_finding", "other-finding"}} {
		denied(row.typ, row.id)
	}
	for _, source := range []struct {
		id, typ  string
		subjects []struct{ typ, id string }
	}{
		{"ev-sbom", "sbom", []struct{ typ, id string }{{"sbom", "sbom"}}},
		{"ev-scan", "vulnerability_scan", []struct{ typ, id string }{{"vulnerability_scan", "scan"}, {"finding", "finding"}, {"vulnerability_finding", "finding"}, {"vulnerability_decision", "decision"}}},
		{"ev-vex", "vex", []struct{ typ, id string }{{"vex", "vex"}}},
		{"ev-contract", "openapi_contract", []struct{ typ, id string }{{"openapi_contract", "contract"}}},
		{"ev-attestation", "build_attestation", []struct{ typ, id string }{{"build_attestation", "attestation"}}},
	} {
		exec(`UPDATE evidence_items SET type='wrong_type' WHERE id=$1`, source.id)
		for _, subject := range source.subjects {
			denied(subject.typ, subject.id)
		}
		exec(`UPDATE evidence_items SET type=$2,product_id='other-product' WHERE id=$1`, source.id, source.typ)
		for _, subject := range source.subjects {
			denied(subject.typ, subject.id)
		}
		exec(`UPDATE evidence_items SET product_id='product' WHERE id=$1`, source.id)
	}
	exec(`UPDATE sboms SET release_id='wrong-release' WHERE id='sbom'`)
	denied("sbom", "sbom")
	exec(`UPDATE sboms SET release_id='release' WHERE id='sbom'`)
	exec(`UPDATE sboms SET artifact_id='other-artifact' WHERE id='sbom'`)
	denied("sbom", "sbom")
	exec(`UPDATE sboms SET artifact_id=NULL WHERE id='sbom'`)
	exec(`UPDATE vex_documents SET artifact_id='other-artifact' WHERE id='vex'`)
	denied("vex", "vex")
	exec(`UPDATE vex_documents SET artifact_id=NULL WHERE id='vex'`)
	exec(`UPDATE vulnerability_decisions SET finding_id='missing' WHERE id='decision'`)
	denied("vulnerability_decision", "decision")
	exec(`UPDATE vulnerability_decisions SET finding_id='finding' WHERE id='decision'`)
	exec(`UPDATE build_runs SET project_id='other-project' WHERE id='build'`)
	denied("build", "build")
	denied("build_attestation", "attestation")
	exec(`UPDATE build_runs SET project_id='project' WHERE id='build'`)
	exec(`UPDATE security_controls SET framework_id='other-fw' WHERE id='control'`)
	denied("product", "product")
	exec(`UPDATE security_controls SET framework_id='fw' WHERE id='control'`)
	exec(`INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version)VALUES('other-control','other','other-fw','C','Other','Other','[]','[]','[]','security-control.v1.0.0')`)
	if v, err := commands.LinkControlEvidence(ctx, actor, "other-control", riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high"}); !errors.Is(err, riskapp.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign control accepted", v.ID, err)
	}
	exec(`INSERT INTO vulnerability_scans SELECT(jsonb_populate_record(NULL::vulnerability_scans,to_jsonb(s)||'{"id":"scan-twin"}'::jsonb)).* FROM vulnerability_scans s WHERE s.id='scan'`)
	for _, typ := range []string{"finding", "vulnerability_finding"} {
		if v, err := commands.LinkControlEvidence(ctx, actor, "control", riskapp.LinkControlEvidenceInput{EvidenceType: "vulnerability_scan", SubjectType: typ, SubjectID: "finding", Confidence: "high"}); !errors.Is(err, riskapp.ErrConflict) || v.ID != "" {
			t.Fatal("ambiguous finding accepted", v.ID, err)
		}
	}
	var links, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries)`).Scan(&links, &audits); err != nil || links != 0 || audits != 0 {
		t.Fatal("denial published effects", links, audits, err)
	}
}

func TestPostgresControlEvidenceCommandsArtifactFiltersUseMatchingPermittedAssociations(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product-b','tenant','Other association','product-b');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project-b','tenant','product-b','Other');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release-b','tenant','product-b','1','draft');INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-associated","product_id":"product-b","project_id":"project-b","release_id":"release-b","subject_refs":[{"type":"artifact","id":"artifact"}]}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest)VALUES('detached','tenant','Detached','application/json',1,'sha256:detached')`)
	cmd, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project-b", Scopes: []string{"controls:write"}}}}
	input := riskapp.LinkControlEvidenceInput{EvidenceType: "artifact", SubjectType: "artifact", SubjectID: "artifact", Confidence: "high"}
	for _, scope := range []struct{ product, release string }{{"", ""}, {"product-b", ""}, {"", "release-b"}, {"product-b", "release-b"}} {
		input.ProductID, input.ReleaseID = scope.product, scope.release
		if v, err := cmd.LinkControlEvidence(ctx, actor, "control", input); err != nil || v.ProductID != scope.product || v.ReleaseID != scope.release {
			t.Fatal("authorized association rejected", scope, v.ID, err)
		}
	}
	for _, scope := range []struct{ product, release string }{{"product", ""}, {"", "release"}, {"product", "release"}} {
		input.ProductID, input.ReleaseID = scope.product, scope.release
		if v, err := cmd.LinkControlEvidence(ctx, actor, "control", input); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
			t.Fatal("grant from different association accepted", scope, v.ID, err)
		}
	}
	input.SubjectID, input.ProductID, input.ReleaseID = "detached", "", ""
	if v, err := cmd.LinkControlEvidence(ctx, actor, "control", input); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("detached artifact visible to scoped grant", v.ID, err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:write"}}}
	if _, err := cmd.LinkControlEvidence(ctx, actor, "control", input); err != nil {
		t.Fatal("tenant grant denied detached artifact", err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"controls:write"}}}
	input.SubjectID = "artifact"
	exec(`UPDATE build_runs SET outputs='[{"artifact_id":"artifact","digest":"sha256:wrong"}]' WHERE id='build'`)
	if v, err := cmd.LinkControlEvidence(ctx, actor, "control", input); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("wrong digest build conferred artifact grant", v.ID, err)
	}
}

func TestPostgresControlEvidenceCommandsAcceptExactKeyBudgetAndPendingSubjects(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	cmd, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:write"}}
	product := strings.Repeat("p", 1024)
	release := strings.Repeat("r", 992)
	if _, err := pool.Exec(ctx, `WITH parent AS(INSERT INTO products(id,tenant_id,name,slug)VALUES($1,'tenant','Large','large')RETURNING id) INSERT INTO releases(id,tenant_id,product_id,version,state)SELECT $2,'tenant',id,'1','draft' FROM parent`, product, release); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||jsonb_build_object('id','subject','product_id',$1::text,'release_id',$2::text))).* FROM evidence_items e WHERE id='ev-sbom'`, product, release); err != nil {
		t.Fatal(err)
	}
	input := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "subject", ProductID: product, ReleaseID: release, Confidence: "high", Notes: strings.Repeat("n", 65536)}
	first, err := cmd.LinkControlEvidence(ctx, actor, "control", input)
	if err != nil || first.Notes != input.Notes {
		t.Fatal("exact budgets rejected", first.ID, err)
	}
	if v, err := cmd.LinkControlEvidence(ctx, actor, "control", input); err != nil || v != first {
		t.Fatal("exact duplicate rejected", v.ID, err)
	}
	rollback := errors.New("outer rollback")
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, actor, "POST", "/v1/security-controls/control/evidence", "pending", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		if err := repos.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "pending", TenantID: "tenant", Name: "Pending", Slug: "pending", CreatedAt: time.Now().UTC()}); err != nil {
			return 0, nil, err
		}
		v, err := cmd.LinkControlEvidence(ctx, actor, "control", riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "pending", Confidence: "high"})
		if err != nil {
			return 0, nil, err
		}
		if v.SubjectID != "pending" {
			return 0, nil, errors.New("pending subject changed")
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("pending subject read outside transaction", err)
	}
	var pending, links, audits int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products WHERE id='pending'),(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries)`).Scan(&pending, &links, &audits); err != nil || pending != 0 || links != 1 || audits != 1 {
		t.Fatal("outer rollback published pending effects", pending, links, audits, err)
	}
}
