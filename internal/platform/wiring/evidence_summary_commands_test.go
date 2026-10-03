package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func seedSummaryMetadata(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
INSERT INTO tenants(id,name)VALUES('tenant','Summary'),('other','Other') ON CONFLICT DO NOTHING;
INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('other-product','other','Other','other'),('second-product','tenant','Second','second');
INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project');
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('second-release','tenant','second-product','2','draft');
INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('build','tenant','project','release','ci','commit','succeeded',now(),'[]','build-run.v1');
INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('package','tenant','product','release','redaction','Package','published','{"private":"do-not-load-manifest"}','sha256:package',now()+interval '1 hour','customer-security-package.v1',now());
INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref,source_identity)
VALUES('a','tenant','product','project','release','build','Build','ci',now(),'evidence.v1','sha256:payload','sha256:aaa','v1','recorded','not_evaluated','private-payload-ref','{"private":"do-not-load-evidence"}'),
('b','tenant',NULL,'project','release','sbom','SBOM','ci',now(),'evidence.v1','sha256:payload','sha256:bbb','v1','recorded','not_evaluated','private-payload-ref','{}'),
('outside','tenant','second-product',NULL,'second-release','note','Outside','ci',now(),'evidence.v1','sha256:payload','sha256:ccc','v1','recorded','not_evaluated','private-payload-ref','{}'),
('foreign','other','other-product',NULL,NULL,'note','Foreign','ci',now(),'evidence.v1','sha256:payload','sha256:ddd','v1','recorded','not_evaluated','private-payload-ref','{}')`); err != nil {
		t.Fatal(err)
	}
}
func summaryWiringCounts(t *testing.T, pool *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM evidence_summaries),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestPostgresSummaryCommandsPreserveAllRootSelectionSemantics(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, pool)
	c, err := BuildEvidenceSummaryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildEvidenceSummaryCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	for _, test := range []struct {
		kind, id string
		ids      []string
	}{{"tenant", "tenant", []string{"a", "b", "outside"}}, {"product", "product", []string{"a"}}, {"release", "release", []string{"a"}}, {"build", "build", []string{"a", "b"}}, {"evidence", "b", []string{"a", "b"}}, {"customer_package", "package", []string{"a"}}} {
		t.Run(test.kind, func(t *testing.T) {
			v, err := c.CreateEvidenceSummary(t.Context(), a, packageapp.CreateEvidenceSummaryInput{SubjectType: test.kind, SubjectID: test.id})
			if err != nil || !reflect.DeepEqual(v.EvidenceIDs, test.ids) {
				t.Fatal("scope semantics changed", v.EvidenceIDs, err)
			}
			var hash, actor string
			if err := pool.QueryRow(t.Context(), `SELECT s.citations->0->>'canonical_hash',a.actor_id FROM evidence_summaries s JOIN audit_chain_entries a ON a.subject_id=s.id AND a.tenant_id=s.tenant_id WHERE s.id=$1`, v.ID).Scan(&hash, &actor); err != nil || hash != "sha256:aaa" || actor != "operator" {
				t.Fatal("citation/audit not persisted", err)
			}
		})
	}
	before := summaryWiringCounts(t, pool)
	for _, test := range []struct {
		in   packageapp.CreateEvidenceSummaryInput
		want error
	}{{packageapp.CreateEvidenceSummaryInput{SubjectType: "tenant", SubjectID: "other"}, packageapp.ErrNotFound}, {packageapp.CreateEvidenceSummaryInput{SubjectType: "evidence", SubjectID: "foreign"}, packageapp.ErrNotFound}, {packageapp.CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: "release", EvidenceIDs: []string{"b"}}, packageapp.ErrValidation}, {packageapp.CreateEvidenceSummaryInput{SubjectType: "tenant", SubjectID: "tenant", EvidenceIDs: []string{"foreign"}}, packageapp.ErrNotFound}} {
		v, err := c.CreateEvidenceSummary(t.Context(), a, test.in)
		if !errors.Is(err, test.want) || v.ID != "" {
			t.Fatal("invalid root/selection accepted", v, err)
		}
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"report:read"}}}}
	in := packageapp.CreateEvidenceSummaryInput{SubjectType: "evidence", SubjectID: "b"}
	if err := c.AuthorizeCreateEvidenceSummary(t.Context(), human, in); err != nil {
		t.Fatal("resolved project scope rejected", err)
	}
	human.ResourceGrants = nil
	if err := c.AuthorizeCreateEvidenceSummary(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant accepted", err)
	}
	if summaryWiringCounts(t, pool) != before {
		t.Fatal("guard or invalid input published summary")
	}
}
func TestPostgresSummaryBoundsAndInsertAuditCommitRollback(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, pool)
	c, err := BuildEvidenceSummaryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	in := packageapp.CreateEvidenceSummaryInput{SubjectType: "product", SubjectID: "product"}
	for _, stage := range []string{"evidence_summaries", "audit_chain_entries", "commit"} {
		setup := `CREATE OR REPLACE FUNCTION reject_summary_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private summary storage';END$$;`
		table := stage
		if stage == "commit" {
			table = "evidence_summaries"
			setup += `CREATE CONSTRAINT TRIGGER reject_summary_stage AFTER INSERT ON evidence_summaries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_summary_stage()`
		} else {
			setup += `CREATE TRIGGER reject_summary_stage BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_summary_stage()`
		}
		if _, err := pool.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		v, err := c.CreateEvidenceSummary(t.Context(), a, in)
		if err == nil || v.ID != "" || summaryWiringCounts(t, pool) != [3]int{} {
			t.Fatal("partial summary escaped", stage, err)
		}
		if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_summary_stage ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE evidence_items SET title=repeat('x',65537) WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateEvidenceSummary(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" {
		t.Fatal("oversized metadata accepted", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE evidence_items SET title='Build' WHERE id='a';INSERT INTO evidence_items(id,tenant_id,product_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)SELECT 'extra-'||n,'tenant','product','note','Note','ci',now(),'evidence.v1','sha256:payload','sha256:hash','v1','recorded','not_evaluated' FROM generate_series(1,512)n`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateEvidenceSummary(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" || summaryWiringCounts(t, pool) != [3]int{} {
		t.Fatal("auto selection silently truncated", err)
	}
	in.EvidenceIDs = []string{"a"}
	if v, err := c.CreateEvidenceSummary(t.Context(), a, in); err != nil || !reflect.DeepEqual(v.EvidenceIDs, []string{"a"}) {
		t.Fatal("bounded explicit selection failed", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE evidence_items SET title=repeat('x',30000) WHERE id LIKE 'extra-%'`); err != nil {
		t.Fatal(err)
	}
	in.EvidenceIDs = nil
	for i := 1; i <= 80; i++ {
		in.EvidenceIDs = append(in.EvidenceIDs, fmt.Sprintf("extra-%d", i))
	}
	if v, err := c.CreateEvidenceSummary(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" || summaryWiringCounts(t, pool) != [3]int{1, 1, 0} {
		t.Fatal("encoded output budget did not roll back", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE evidence_items SET title=repeat('x',65536) WHERE id LIKE 'extra-%'`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateEvidenceSummary(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" || summaryWiringCounts(t, pool) != [3]int{1, 1, 0} {
		t.Fatal("selected metadata budget not enforced", err)
	}
}
func summaryHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.EvidenceSummaryCommands == nil {
		t.Fatal("summary still Ledger-backed", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/evidence-summaries", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-payload-ref") || strings.Contains(w.Body.String(), "do-not-load") || strings.Contains(w.Body.String(), "private summary storage") {
		t.Fatalf("unsafe/legacy summary status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	return w.Body.String()
}
func TestPostgresSummaryHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, pool)
	seedSummaryMetadata(t, pool)
	body := `{"subject_type":"evidence","subject_id":"b"}`
	first := summaryHTTP(t, store, "summary", body, 201)
	second := summaryHTTP(t, store, "summary", body, 201)
	var left, right any
	if json.Unmarshal([]byte(first), &left) != nil || json.Unmarshal([]byte(second), &right) != nil || !reflect.DeepEqual(left, right) || summaryWiringCounts(t, pool) != [3]int{1, 1, 1} {
		t.Fatal("replay changed summary/effects")
	}
	summaryHTTP(t, store, "summary", `{"subject_type":"product","subject_id":"product"}`, 409)
	if _, err := pool.Exec(t.Context(), `UPDATE role_bindings SET role='evidence_viewer',resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	summaryHTTP(t, store, "summary", body, 403)
	if summaryWiringCounts(t, pool) != [3]int{1, 1, 1} {
		t.Fatal("denied replay changed summary")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin',resource_type='tenant',resource_id='tenant' WHERE id='grant';CREATE FUNCTION reject_summary_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private summary storage';END$$;CREATE CONSTRAINT TRIGGER reject_summary_http AFTER INSERT ON evidence_summaries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_summary_http()`); err != nil {
		t.Fatal(err)
	}
	summaryHTTP(t, store, "rollback", body, 500)
	if summaryWiringCounts(t, pool) != [3]int{1, 1, 1} {
		t.Fatal("failed HTTP command committed partial effects")
	}
}
func TestPostgresSummaryFencePrecedesRootLocks(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, pool)
	c, err := BuildEvidenceSummaryCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- c.AuthorizeCreateEvidenceSummary(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"report:read"}}, packageapp.CreateEvidenceSummaryInput{SubjectType: "evidence", SubjectID: "a"})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("summary bypassed fence", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if !waiting {
				continue
			}
			if _, err := leader.Exec(ctx, `SELECT id FROM evidence_items WHERE id='a' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("root lock precedes fence", err)
			}
			if err := leader.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(fmt.Errorf("summary fence did not resume: %w", ctx.Err()))
			}
			return
		}
	}
}
