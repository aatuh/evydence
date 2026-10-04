package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func anomalyWiringCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var n [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM anomaly_reports),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
		t.Fatal(err)
	}
	return n
}
func seedAnomalyBuildFacts(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest)VALUES('artifact','tenant','Artifact','application/octet-stream',1,$1)`, []any{digest}},
		{`UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact"}]' WHERE id='a'`, nil},
		{`UPDATE build_runs SET status='passed',outputs=jsonb_build_array(jsonb_build_object('digest',$1::text)) WHERE id='build'`, []any{digest}},
		{`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,type,title,source_system,observed_at,schema_version,payload_hash,payload_size,canonical_hash,canonicalization,trust_level,verification_status) VALUES('attestation_source','tenant','product','project','release','build','build_attestation','Attestation','ci',now(),'evidence.v1','sha256:test',1,'sha256:test','v1','recorded','not_evaluated')`, nil},
		{`INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version)VALUES('attestation','tenant','build','attestation_source','sha256:test',1,'application/json','test',jsonb_build_array($1::text),0,1,'passed','attestation.v1')`, []any{digest}},
		{`INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at,assurance_profile,schema_version)VALUES('receipt','tenant','build_attestation','attestation','passed','[]',now(),'{"id":"dsse-attestation-signature.v1"}','verification-result.v2.0.0')`, nil},
	} {
		if _, err := p.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPostgresAnomalyCommandsUseOnlyScopedFactsAndAtomicWrites(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildAnomalyReportCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAnomalyReportCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	for _, root := range [][2]string{{"tenant", "tenant"}, {"product", "product"}, {"release", "release"}, {"build", "build"}, {"evidence", "b"}, {"customer_package", "package"}} {
		v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: root[0], SubjectID: root[1]})
		if err != nil || v.SubjectType != root[0] || v.SubjectID != root[1] || root[0] == "release" && len(v.Signals) != 2 || root[0] != "release" && v.Result != "clear" {
			t.Fatal("anomaly root semantics changed", v, err)
		}
	}
	before := anomalyWiringCounts(t, p)
	for _, root := range [][2]string{{"tenant", "other"}, {"product", "other-product"}, {"evidence", "foreign"}, {"release", "missing"}} {
		if v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: root[0], SubjectID: root[1]}); !errors.Is(err, experimentalapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign root accepted", v, err)
		}
	}
	human := a
	human.KeyID, human.UserID = "", "user"
	if v, err := c.GenerateAnomalyReport(t.Context(), human, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unscoped human read anomaly facts", err)
	}
	for _, stage := range []string{"anomaly_reports", "audit_chain_entries", "commit"} {
		target := stage
		sql := `CREATE OR REPLACE FUNCTION reject_anomaly_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private anomaly failure';END$$;`
		if stage == "commit" {
			target = "anomaly_reports"
			sql += `CREATE CONSTRAINT TRIGGER reject_anomaly_write AFTER INSERT ON anomaly_reports DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_anomaly_write()`
		} else {
			sql += `CREATE TRIGGER reject_anomaly_write BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_anomaly_write()`
		}
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"})
		if err == nil || v.ID != "" || anomalyWiringCounts(t, p) != before {
			t.Fatal("failed anomaly write published partial state", stage, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_anomaly_write ON `+target); err != nil {
			t.Fatal(err)
		}
	}
	seedAnomalyBuildFacts(t, p)
	v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"})
	if err != nil || v.Result != "clear" {
		t.Fatal("trusted release facts not recognized", v, err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE verification_results SET assurance_profile='{"id":"metadata-only"}' WHERE id='receipt'`); err != nil {
		t.Fatal(err)
	}
	v, err = c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"})
	if err != nil || len(v.Signals) != 1 || v.Signals[0].Name != "missing_matching_attestation" {
		t.Fatal("metadata-only receipt trusted", v, err)
	}
	// A full readiness snapshot rejects this unrelated package count. The anomaly
	// port must expose only its three booleans, never load package snapshots.
	if _, err := p.Exec(t.Context(), `INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)SELECT 'irrelevant-'||n,'tenant','product','release','redaction','Package','generated','{}','sha256:test',now()+interval '1 hour','package.v1',now() FROM generate_series(1,4097)n`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"}); err != nil || len(v.Signals) != 1 {
		t.Fatal("anomaly unnecessarily loaded readiness packages", v, err)
	}
}
func TestPostgresAnomalyCriticalDecisionAndExceptionFacts(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	seedAnomalyBuildFacts(t, p)
	c, err := BuildAnomalyReportCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	in := experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"}
	if _, err := p.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES('scan_source','tenant','product','project','release','vulnerability_scan','Scan','ci',now(),'evidence.v1','sha256:test','sha256:test','v1','recorded','not_evaluated'); INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings)VALUES('scan','tenant','scan_source','release','test','target','{}','[{"id":"finding","vulnerability":"CVE-TEST","severity":"critical","state":"open"}]')`); err != nil {
		t.Fatal(err)
	}
	want := func(critical bool) {
		t.Helper()
		v, err := c.GenerateAnomalyReport(t.Context(), a, in)
		if err != nil || critical && (len(v.Signals) != 1 || v.Signals[0].Name != "unhandled_critical_finding") || !critical && v.Result != "clear" {
			t.Fatal("current critical handling differs", v, err)
		}
	}
	want(true)
	if _, err := p.Exec(t.Context(), `INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version)VALUES('decision','tenant','finding','scan','release','CVE-TEST','fixed','fixed','manual','decision.v1')`); err != nil {
		t.Fatal(err)
	}
	want(false)
	if _, err := p.Exec(t.Context(), `UPDATE vulnerability_decisions SET superseded_by='new' WHERE id='decision';INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version)VALUES('new','tenant','finding','scan','release','CVE-TEST','affected','current','manual','decision.v1')`); err != nil {
		t.Fatal(err)
	}
	want(true)
	if _, err := p.Exec(t.Context(), `INSERT INTO exceptions(id,tenant_id,release_id,finding_id,reason,owner,expires_at,approved,approved_by,approved_at)VALUES('exception','tenant','release','finding','reviewed','reviewer',now()+interval '1 hour',true,'reviewer',now())`); err != nil {
		t.Fatal(err)
	}
	want(false)
	if _, err := p.Exec(t.Context(), `UPDATE exceptions SET expires_at=now()-interval '1 second' WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	want(true)
	if _, err := p.Exec(t.Context(), `UPDATE vulnerability_scans SET findings='{}' WHERE id='scan'`); err != nil {
		t.Fatal(err)
	}
	before := anomalyWiringCounts(t, p)
	if v, err := c.GenerateAnomalyReport(t.Context(), a, in); !errors.Is(err, experimentalapp.ErrValidation) || v.ID != "" || anomalyWiringCounts(t, p) != before {
		t.Fatal("malformed findings accepted", err)
	}
	if v, err := c.GenerateAnomalyReport(t.Context(), a, experimentalapp.AnomalyReportInput{SubjectType: "product", SubjectID: "product"}); err != nil || v.Result != "clear" {
		t.Fatal("non-release root loaded release findings", v, err)
	}
}
func TestPostgresAnomalyHTTPRestartReplayCurrentGrantAndNoLedgerReload(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedSummaryMetadata(t, p)
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.AnomalyReportCommands == nil {
			t.Fatal("anomaly remains Ledger-backed", err)
		}
		noReload := &decisionHTTPNoReloadStore{}
		l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/reports/anomaly", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 {
			t.Fatal("anomaly response or Ledger refresh differs", w.Code, want, noReload.loads, w.Body.String())
		}
		return w.Body.Bytes()
	}
	const body = `{"subject_type":"release","subject_id":"release"}`
	first := request("anomaly", body, 201)
	before := anomalyWiringCounts(t, p)
	seedAnomalyBuildFacts(t, p)
	var original, replay any
	if err := json.Unmarshal(first, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request("anomaly", body, 201), &replay); err != nil || !reflect.DeepEqual(original, replay) || anomalyWiringCounts(t, p) != before {
		t.Fatal("replay regenerated anomaly after facts changed", err)
	}
	request("anomaly", strings.Replace(body, "release\"}", "second-release\"}", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("anomaly", body, 403)
	request("denied", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='release' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("anomaly", body, 201)
	if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_anomaly_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private anomaly commit';END$$;CREATE CONSTRAINT TRIGGER reject_anomaly_commit AFTER INSERT ON anomaly_reports DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_anomaly_commit()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit-failure", body, 500)
	if strings.Contains(string(failed), "private anomaly commit") || strings.Contains(string(failed), "attention_required") || strings.Contains(string(failed), `"result":"clear"`) || anomalyWiringCounts(t, p) != before {
		t.Fatal("HTTP commit failure published report or partial effects")
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM releases WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("anomaly", body, 404)
	if anomalyWiringCounts(t, p) != before {
		t.Fatal("replay guards mutated anomaly metadata")
	}
}

func TestPostgresAnomalyHoldsRootLocksAndWorkerFenceThroughReplayCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildAnomalyReportCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/reports/anomaly", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.GenerateAnomalyReport(ctx, a, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "release"})
		if err != nil {
			return 0, nil, err
		}
		for _, sql := range []string{`SELECT 1 FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT 1 FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT 1 FROM releases WHERE id='release' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, sql)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("anomaly root lock missing")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT 1 FROM evidence_items WHERE id='outside' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, errors.New("anomaly locked unrelated evidence")
		}
		tx, err = p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
			_ = tx.Rollback(ctx)
			return 0, nil, err
		}
		lockErr := coordination.LockWorkerProjection(ctx, tx, "tenant")
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
			return 0, nil, errors.New("anomaly worker projection fence missing")
		}
		return 201, v, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
