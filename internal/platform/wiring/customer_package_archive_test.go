package wiring

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func seedArchivePackages(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('foreign-product','other','Other','other');
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft');
INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('profile','tenant','Profile',ARRAY['sbom'],ARRAY['internal_notes'],'redaction.v1',now()),('foreign-profile','other','Other',ARRAY['sbom'],ARRAY['internal_notes'],'redaction.v1',now());
UPDATE tenants SET name=repeat('private unrelated tenant state',300000)WHERE id='other';`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('package','tenant','product','release','profile','Review','generated','{"evidence_ids":["ev_frozen"],"internal_notes":"private archive notes"}',$1,now()+interval '1 hour','customer-security-package.v2.0.0',now()),('foreign','other','foreign-product',NULL,'foreign-profile','Foreign','generated','{"evidence_ids":["private foreign evidence"]}',$1,now()+interval '1 hour','customer-security-package.v2.0.0',now())`, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func archiveAccessCounts(t *testing.T, p *pgxpool.Pool) [2]int {
	t.Helper()
	var out [2]int
	if err := p.QueryRow(t.Context(), `SELECT access_count,(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant')FROM customer_security_packages WHERE id='package'`).Scan(&out[0], &out[1]); err != nil {
		t.Fatal(err)
	}
	return out
}

func packageArchiveHTTP(t *testing.T, store *postgres.Store, path string, want int) *httptest.ResponseRecorder {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.CustomerPackageAccessCommands == nil {
		t.Fatal("missing focused package access", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", path, nil).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private archive storage") {
		t.Fatalf("archive status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want != 200 && (w.Header().Get("Content-Disposition") != "" || w.Header().Get("X-Evydence-Archive-Hash") != "") {
		t.Fatal("failed archive published download headers")
	}
	return w
}

func TestPostgresCustomerArchiveRestartScopeExpiryAndAuditRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedArchivePackages(t, p)
	const path = "/v1/customer-packages/package/download"
	for range 2 {
		w := packageArchiveHTTP(t, store, path, 200)
		digest := sha256.Sum256(w.Body.Bytes())
		if w.Header().Get("Content-Type") != "application/zip" || w.Header().Get("X-Evydence-Archive-Hash") != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Fatal("ZIP headers/hash differ")
		}
		reader, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
		if err != nil || len(reader.File) != 5 {
			t.Fatal("ZIP shape invalid", err)
		}
		found := false
		for _, entry := range reader.File {
			if strings.Contains(entry.Name, "/") || strings.Contains(entry.Name, "\\") || entry.UncompressedSize64 > 1<<20 {
				t.Fatal("unsafe ZIP entry")
			}
			f, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			closeErr := f.Close()
			if err != nil || closeErr != nil || len(raw) > 1<<20 {
				t.Fatal("ZIP read failed")
			}
			if bytes.Contains(raw, []byte("private archive notes")) || bytes.Contains(raw, []byte("private foreign evidence")) || bytes.Contains(raw, []byte("private unrelated tenant state")) {
				t.Fatal("archive leaked private/unrelated state")
			}
			if entry.Name == "manifest.json" {
				var m map[string]any
				if json.Unmarshal(raw, &m) != nil || m["internal_notes"] != nil || !bytes.Contains(raw, []byte("ev_frozen")) {
					t.Fatal("frozen public manifest changed")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing manifest")
		}
	}
	if archiveAccessCounts(t, p) != [2]int{2, 2} {
		t.Fatal("restarted downloads did not audit each access")
	}
	for _, bad := range []string{"foreign", "missing", "bad%00", strings.Repeat("x", 1025)} {
		want := 404
		if bad == "bad%00" || len(bad) > 1024 {
			want = 400
		}
		packageArchiveHTTP(t, store, "/v1/customer-packages/"+bad+"/download", want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='different'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	packageArchiveHTTP(t, store, path, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE customer_security_packages SET expires_at=now()-interval '1 hour'WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	packageArchiveHTTP(t, store, path, 409)
	if archiveAccessCounts(t, p) != [2]int{2, 2} {
		t.Fatal("failed scopes/expiry changed audit/count")
	}
	if _, err := p.Exec(t.Context(), `UPDATE customer_security_packages SET expires_at=now()+interval '1 hour'WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"audit", "commit"} {
		trigger := `CREATE TRIGGER reject_archive_access BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_archive_access()`
		if stage == "commit" {
			trigger = `CREATE CONSTRAINT TRIGGER reject_archive_access AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_archive_access()`
		}
		if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_archive_access()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private archive storage';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		packageArchiveHTTP(t, store, path, 500)
		if archiveAccessCounts(t, p) != [2]int{2, 2} {
			t.Fatal("failed archive access committed partial audit/count", stage)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_archive_access ON audit_chain_entries`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	packageArchiveHTTP(t, store, path, 401)
	var storedNotes string
	if err := p.QueryRow(t.Context(), `SELECT manifest->>'internal_notes'FROM customer_security_packages WHERE id='package'`).Scan(&storedNotes); err != nil || storedNotes != "private archive notes" || archiveAccessCounts(t, p) != [2]int{2, 2} {
		t.Fatal("download changed immutable manifest or failed access count", err)
	}
}

func TestPostgresCustomerArchiveFencePrecedesPackageLock(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedArchivePackages(t, p)
	c, err := BuildCustomerPackageAccessCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.AccessCustomerSecurityPackage(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:read"}}, "package")
		done <- err
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("access bypassed writer fence", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			if _, err := leader.Exec(ctx, `SELECT id FROM customer_security_packages WHERE id='package'FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("package row locked before common writer fence", err)
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
				t.Fatal("package access did not resume", ctx.Err())
			}
			if archiveAccessCounts(t, p) != [2]int{1, 1} {
				t.Fatal("access effects did not commit together")
			}
			return
		}
	}
}
