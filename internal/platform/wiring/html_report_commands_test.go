package wiring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type craReportQueryFunc func(context.Context, identitydomain.Actor, string, string) (packagedomain.CRAReadinessReport, error)

func (f craReportQueryFunc) CRAReadiness(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.CRAReadinessReport, error) {
	return f(ctx, actor, productID, releaseID)
}

func TestHTMLReportWiringPreservesActorAndRepositoryContract(t *testing.T) {
	memory := app.NewMemoryUnitOfWorkFactory()
	now := time.Now().UTC()
	if err := app.ExecuteUnitOfWork(t.Context(), memory, func(ctx context.Context, repos app.Repositories) error {
		if err := repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_html", Name: "HTML", CreatedAt: now}); err != nil {
			return err
		}
		return repos.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_html", TenantID: "ten_html", Name: "HTML", Slug: "html", CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_html", UserID: "usr_html", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_html", Scopes: []string{"report:read"}}}}
	calls := 0
	query := craReportQueryFunc(func(_ context.Context, actual identitydomain.Actor, productID, releaseID string) (packagedomain.CRAReadinessReport, error) {
		calls++
		if !reflect.DeepEqual(actual, actor) {
			t.Fatal("actor/grants replaced at query boundary")
		}
		return packagedomain.CRAReadinessReport{ProductID: productID, ReleaseID: releaseID, Result: "unknown", Limitations: []string{"<independent review>"}}, nil
	})
	commands, err := BuildHTMLReportCommands(query, memory)
	if err != nil {
		t.Fatal(err)
	}
	report, err := commands.CRAReadinessHTMLPackage(t.Context(), actor, "prod_html", "")
	if err != nil || !strings.Contains(report.HTML, "&lt;independent review&gt;") || report.Hash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(report.HTML))) {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	state, err := memory.Snapshot()
	if err != nil || state.HTMLReports[report.ID].HTML != report.HTML || len(state.AuditEntries[actor.TenantID]) != 1 {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	actor.ResourceGrants = nil
	if result, err := commands.CRAReadinessHTMLPackage(t.Context(), actor, "prod_html", ""); !errors.Is(err, application.ErrForbidden) || result.ID != "" || calls != 1 {
		t.Fatalf("unauthorized result=%#v err=%v calls=%d", result, err, calls)
	}
	if _, err := BuildHTMLReportCommands(nil, memory); err == nil {
		t.Fatal("nil query accepted")
	}
	if _, err := BuildHTMLReportCommands(query, nil); err == nil {
		t.Fatal("nil factory accepted")
	}
}

func openHTMLReportWiringStore(t *testing.T) (*postgres.Store, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("evydence_html_report_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	params := parsed.Query()
	params.Set("search_path", schema)
	parsed.RawQuery = params.Encode()
	store, err := postgres.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	nativeHTTPFixturePools.Store(store, pool)
	t.Cleanup(func() { nativeHTTPFixturePools.Delete(store) })
	return store, pool
}

func TestPostgresHTMLReportCommandsCommitReportAndAuditWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('ten_html','HTML'),('ten_other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('prod_html','ten_html','HTML','html'),('prod_other','ten_other','Other','other'),('prod_second','ten_html','Second','second')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('rel_html','ten_html','prod_html','1','draft'),('rel_second','ten_html','prod_second','2','draft')`)
	exec(`INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version) VALUES('fw_html','ten_html','Framework','framework','1','active','control-framework.v1.0.0')`)
	exec(`INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version) VALUES('ctrl_html','ten_html','fw_html','C1','Control','private-objective-marker','[{"type":"sbom","required":true}]','[]','[]','security-control.v1.0.0')`)
	query, err := BuildControlCoverageQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	commands, err := BuildHTMLReportCommands(query, store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_html", UserID: "usr_html", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_html", Scopes: []string{"report:read"}}}}
	canonical, err := query.CRAReadiness(ctx, actor, "prod_html", "rel_html")
	if err != nil {
		t.Fatal(err)
	}
	report, err := commands.CRAReadinessHTMLPackage(ctx, actor, "prod_html", "rel_html")
	if err != nil || !strings.Contains(report.HTML, "Result: "+canonical.Result) || strings.Contains(report.HTML, "private-objective-marker") {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	for _, limitation := range canonical.Limitations {
		if !strings.Contains(report.HTML, limitation) {
			t.Fatal("canonical limitation missing")
		}
	}
	var storedHTML, hash, auditHash string
	if err := pool.QueryRow(ctx, `SELECT r.html,r.hash,a.payload_hash FROM html_report_packages r JOIN audit_chain_entries a ON a.tenant_id=r.tenant_id AND a.subject_id=r.id WHERE r.id=$1`, report.ID).Scan(&storedHTML, &hash, &auditHash); err != nil {
		t.Fatal(err)
	}
	if storedHTML != report.HTML || hash != report.Hash || auditHash != hash || hash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(storedHTML))) {
		t.Fatal("stored report/audit hash mismatch")
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.CRAReadinessHTMLPackage(ctx, denied, "prod_html", "rel_html"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	denied = actor
	denied.TenantID = "ten_other"
	denied.KeyID = "key_other"
	if _, err := commands.CRAReadinessHTMLPackage(ctx, denied, "prod_html", "rel_html"); err == nil {
		t.Fatal("foreign tenant generated report")
	}
	if _, err := commands.CRAReadinessHTMLPackage(ctx, actor, "prod_html", "rel_second"); err == nil {
		t.Fatal("wrong product/release pair generated report")
	}
	// The query commits before report persistence. Recheck durable ownership at
	// insert even if the release parent changes between those transactions.
	staleQuery := craReportQueryFunc(func(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.CRAReadinessReport, error) {
		result, err := query.CRAReadiness(ctx, actor, productID, releaseID)
		if err == nil {
			exec(`UPDATE releases SET product_id='prod_second' WHERE id='rel_html'`)
		}
		return result, err
	})
	staleCommands, err := BuildHTMLReportCommands(staleQuery, store)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := staleCommands.CRAReadinessHTMLPackage(ctx, actor, "prod_html", "rel_html"); !errors.Is(err, packageapp.ErrNotFound) || result.ID != "" {
		t.Fatalf("stale report=%#v err=%v", result, err)
	}
	exec(`UPDATE releases SET product_id='prod_html' WHERE id='rel_html'`)
	exec(`CREATE FUNCTION reject_html_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit write failure';END$$`)
	exec(`CREATE TRIGGER reject_html_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_html_audit()`)
	if result, err := commands.CRAReadinessHTMLPackage(ctx, actor, "prod_html", "rel_html"); err == nil || result.ID != "" {
		t.Fatalf("rollback result=%#v err=%v", result, err)
	}
	var reports, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM html_report_packages),(SELECT count(*) FROM audit_chain_entries)`).Scan(&reports, &audits); err != nil {
		t.Fatal(err)
	}
	if reports != 1 || audits != 1 {
		t.Fatalf("failed commands wrote state reports=%d audits=%d", reports, audits)
	}
}
