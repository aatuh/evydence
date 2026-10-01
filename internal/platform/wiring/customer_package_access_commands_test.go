package wiring

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCustomerPackageAccessWiringPreservesMemoryRepositoryContract(t *testing.T) {
	memory := app.NewMemoryUnitOfWorkFactory()
	now := time.Now().UTC()
	err := app.ExecuteUnitOfWork(t.Context(), memory, func(ctx context.Context, repos app.Repositories) error {
		if err := repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_memory_package", Name: "Memory", CreatedAt: now}); err != nil {
			return err
		}
		if err := repos.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_memory_package", TenantID: "ten_memory_package", Name: "Memory", Slug: "memory", CreatedAt: now}); err != nil {
			return err
		}
		if err := repos.Packages.InsertRedactionProfile(ctx, domain.RedactionProfile{ID: "rp_memory_package", TenantID: "ten_memory_package", Name: "Review", AllowedTypes: []string{"sbom"}, SchemaVersion: "redaction.v1", CreatedAt: now}); err != nil {
			return err
		}
		return repos.Packages.InsertCustomerSecurityPackage(ctx, domain.CustomerSecurityPackage{ID: "csp_memory", TenantID: "ten_memory_package", ProductID: "prod_memory_package", RedactionProfileID: "rp_memory_package", Title: "Memory", State: "generated", Manifest: map[string]any{"evidence_ids": []string{"ev_1"}}, ManifestHash: "sha256:" + strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour), SchemaVersion: "package.v1", CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	commands, err := BuildCustomerPackageAccessCommands(memory)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := commands.AccessCustomerSecurityPackage(t.Context(), identitydomain.Actor{TenantID: "ten_memory_package", KeyID: "key_memory", Scopes: []string{"package:read"}}, "csp_memory")
	if err != nil || pkg.AccessCount != 1 || pkg.Title != "Memory" {
		t.Fatalf("pkg=%#v err=%v", pkg, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || snapshot.CustomerPackages[pkg.ID].ManifestHash != pkg.ManifestHash || len(snapshot.AuditEntries[pkg.TenantID]) != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestPostgresCustomerPackageAccessCommitsCountAndAuditWithoutLedger(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("evydence_package_access_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") }()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := postgres.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	exec(`INSERT INTO tenants(id,name)VALUES('ten_access','Access'),('ten_foreign','Foreign')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('prod_access','ten_access','Access','access')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('rel_access','ten_access','prod_access','1','draft')`)
	exec(`INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('rp_access','ten_access','Review',ARRAY['sbom'],'{}','redaction.v1',$1)`, now)
	exec(`INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('csp_access','ten_access','prod_access','rel_access','rp_access','Review','generated','{"evidence_ids":["ev_2","ev_1"],"internal_notes":"private-package-marker"}',$1,$2,'package.v1',$3)`, "sha256:"+strings.Repeat("a", 64), now.Add(time.Hour), now)
	commands, err := BuildCustomerPackageAccessCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_access", UserID: "user_access", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "csp_access", Scopes: []string{"package:read"}}}}
	report, err := commands.SecurityReviewPackageReport(ctx, actor, "csp_access")
	if err != nil || len(report.EvidenceIDs) != 2 || report.EvidenceIDs[0] != "ev_2" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.AccessCustomerSecurityPackage(ctx, denied, "csp_access"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	denied = actor
	denied.TenantID = "ten_foreign"
	if _, err := commands.AccessCustomerSecurityPackage(ctx, denied, "csp_access"); err == nil {
		t.Fatal("foreign tenant read package")
	}
	// Forced audit failure must roll back the already-executed count update.
	exec(`CREATE FUNCTION reject_access_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit write failure';END$$`)
	exec(`CREATE TRIGGER reject_access_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_access_audit()`)
	if result, err := commands.AccessCustomerSecurityPackage(ctx, actor, "csp_access"); err == nil || result.ID != "" {
		t.Fatalf("audit rollback result=%#v err=%v", result, err)
	}
	exec(`DROP TRIGGER reject_access_audit ON audit_chain_entries`)
	const concurrent = 12
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkg, err := commands.AccessCustomerSecurityPackage(ctx, actor, "csp_access")
			if err == nil && pkg.Manifest["internal_notes"] != nil {
				err = errors.New("private package field escaped sanitizer")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count, audits int
	var storedNotes string
	if err := pool.QueryRow(ctx, `SELECT access_count,(SELECT count(*) FROM audit_chain_entries WHERE tenant_id='ten_access'),manifest->>'internal_notes' FROM customer_security_packages WHERE id='csp_access'`).Scan(&count, &audits, &storedNotes); err != nil {
		t.Fatal(err)
	}
	if count != concurrent+1 || audits != count {
		t.Fatalf("count=%d audits=%d want=%d", count, audits, concurrent+1)
	}
	if storedNotes != "private-package-marker" {
		t.Fatal("access rewrote the frozen package manifest")
	}
	exec(`UPDATE customer_security_packages SET expires_at=$1 WHERE id='csp_access'`, now.Add(-time.Hour))
	if result, err := commands.AccessCustomerSecurityPackage(ctx, actor, "csp_access"); err == nil || result.ID != "" {
		t.Fatalf("expired result=%#v err=%v", result, err)
	}
}
