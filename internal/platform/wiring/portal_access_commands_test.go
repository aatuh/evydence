package wiring

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func portalWiringCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM customer_portal_access),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestPostgresPortalHTTPLifecycleRestartReplayAndPrivateMetadata(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedSummaryMetadata(t, p)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	if _, err := p.Exec(ctx, `UPDATE customer_security_packages SET title=repeat('x',9437184),manifest=jsonb_build_object('private',repeat('x',9437184)) WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	request := func(path, key, body, kind string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.PortalAccessCommands == nil || opts.PortalTokenCommands == nil {
			t.Fatal("portal lifecycle still Ledger-backed", err)
		}
		noReload := &decisionHTTPNoReloadStore{}
		l, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, l, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		if key != "" {
			r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
			r.Header.Set("Idempotency-Key", key)
		}
		r.Header.Set("Content-Type", kind)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 {
			t.Fatal("portal response/refresh differs", path, w.Code, want, noReload.loads)
		}
		if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatal("portal failure lacks Problem Details")
		}
		if want == 200 && key == "" && (w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer") {
			t.Fatal("portal consumer lost privacy headers")
		}
		return w.Body.Bytes()
	}
	decode := func(raw []byte) map[string]any {
		t.Helper()
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	bodyBytes, _ := json.Marshal(map[string]any{"package_id": " package ", "customer_name": " Customer ", "reviewer_name": " Reviewer ", "reviewer_email": " PERSON@EXAMPLE.TEST ", "require_nda": true, "watermark": "Customer review copy", "expires_at": time.Now().Add(30 * 24 * time.Hour).UTC()})
	body := string(bodyBytes)
	const create = "/v1/customer-portal/access"
	first := decode(request(create, "portal", body, "application/json", 201))
	access := first["access"].(map[string]any)
	secret := first["secret"].(string)
	if len(secret) != 49 || !strings.HasPrefix(secret, "evycp_") || access["reviewer_email"] != "person@example.test" || access["hash"] != nil || access["package_id"] != "package" || portalWiringCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("portal issuance contract differs")
	}
	before := portalWiringCounts(t, p)
	replay := decode(request(create, "portal", body, "application/json", 201))
	safeAccess, _ := redaction.RemoveSensitive(access)
	if replay["secret"] != nil || !reflect.DeepEqual(safeAccess, replay["access"]) || portalWiringCounts(t, p) != before {
		t.Fatal("restart portal replay reminted token or changed safe historical metadata")
	}
	for _, field := range []string{"customer_name", "reviewer_name", "reviewer_email"} {
		if replay["access"].(map[string]any)[field] != nil {
			t.Fatal("portal replay persisted recipient PII")
		}
	}
	c, _ := identityapp.NewHMACAuthenticationCredentials("receipt-test-pepper")
	var hash, saved string
	if err := p.QueryRow(ctx, `SELECT hash FROM customer_portal_access WHERE id=$1`, access["id"]).Scan(&hash); err != nil || hash != c.Hash(secret) {
		t.Fatal("portal hash compatibility differs", err)
	}
	if err := p.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='portal'`).Scan(&saved); err != nil || strings.Contains(saved, secret) || strings.Contains(saved, hash) || strings.Contains(saved, `"secret"`) || len(saved) > 16384 {
		t.Fatal("portal replay leaked credential/private metadata", err)
	}
	request(create, "portal", strings.Replace(body, " Customer ", "Other", 1), "application/json", 409)
	if _, err := p.Exec(ctx, `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request(create, "portal", body, "application/json", 403)
	request(create+"/"+access["id"].(string)+"/revoke", "denied-revoke", "", "application/json", 403)
	if portalWiringCounts(t, p) != before {
		t.Fatal("current grant denial changed portal rows")
	}
	if _, err := p.Exec(ctx, `UPDATE role_bindings SET resource_type='customer_security_package',resource_id='package' WHERE id='grant';UPDATE customer_security_packages SET title='Package',manifest='{"evidence_ids":[],"limitations":["Scoped review only."]}' WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	tokenBody := `{"token":"` + secret + `"}`
	request("/v1/customer-portal/package", "", tokenBody, "application/json", 403)
	tokenBody = `{"token":"` + secret + `","nda_accepted":true,"nda_accepted_by":" Reviewer "}`
	pkg := decode(request("/v1/customer-portal/package", "", tokenBody, "application/json", 200))
	if pkg["id"] != "package" || pkg["distribution_watermark"] != access["watermark"] {
		t.Fatal("issued portal token cannot immediately access selected package")
	}
	form := url.Values{"token": {secret}, "nda_accepted_by": {"Reviewer"}}
	html := request("/v1/customer-portal/package/view", "", form.Encode(), "application/x-www-form-urlencoded", 200)
	if strings.Contains(string(html), secret) || !strings.Contains(string(html), "Package") {
		t.Fatal("browser portal leaks token or lost package")
	}
	archive := request("/v1/customer-portal/package/download", "", tokenBody, "application/json", 200)
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range z.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("portal archive leaks credential", err)
		}
		if file.Name == "WATERMARK.txt" {
			found = bytes.Contains(raw, []byte(access["watermark"].(string)))
		}
	}
	if !found {
		t.Fatal("portal archive lost recipient watermark")
	}
	revoke := create + "/" + access["id"].(string) + "/revoke"
	revoked := decode(request(revoke, "revoke", "", "application/json", 200))
	if revoked["revoked_at"] == nil || revoked["access_count"] != float64(3) || revoked["nda_accepted_by"] != "Reviewer" || revoked["hash"] != nil {
		t.Fatal("focused revocation overwrote accepted NDA/counters")
	}
	before = portalWiringCounts(t, p)
	request(revoke, "revoke", "", "application/json", 200)
	request(revoke, "revoke-again", "", "application/json", 200)
	if after := portalWiringCounts(t, p); after[0] != before[0] || after[1] != before[1] || after[2] != before[2]+1 {
		t.Fatal("repeat revocation appends duplicate audit")
	}
	request("/v1/customer-portal/package", "", tokenBody, "application/json", 401)
	if _, err := p.Exec(ctx, `UPDATE role_bindings SET resource_id='absent' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request(revoke, "revoke", "", "application/json", 403)
}

func TestPostgresPortalConcurrentAccessAndFailureLimit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	writes, err := BuildPortalAccessCommands(store, "portal-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := BuildPortalTokenCommands(store, store, "portal-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	v, secret, err := writes.CreatePortalAccess(t.Context(), a, packageapp.CreatePortalAccessInput{PackageID: "package", CustomerName: "Customer", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tokens.AccessPortalPackage(t.Context(), secret, packageapp.PortalAcceptanceInput{}, false)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent token access failed", err)
		}
	}
	var successes, failures int
	if err := p.QueryRow(t.Context(), `SELECT access_count,failed_access_count FROM customer_portal_access WHERE id=$1`, v.ID).Scan(&successes, &failures); err != nil || successes != 8 || failures != 0 || portalWiringCounts(t, p) != [3]int{1, 17, 0} {
		t.Fatal("concurrent access lost increments/audits", err)
	}
	bad := secret[:len(secret)-1] + "!"
	for range 8 {
		if _, err := tokens.AccessPortalPackage(t.Context(), bad, packageapp.PortalAcceptanceInput{}, false); !errors.Is(err, application.ErrUnauthorized) {
			t.Fatal("wrong token accepted", err)
		}
	}
	var revoked *time.Time
	if err := p.QueryRow(t.Context(), `SELECT failed_access_count,revoked_at FROM customer_portal_access WHERE id=$1`, v.ID).Scan(&failures, &revoked); err != nil || failures != 5 || revoked == nil {
		t.Fatal("failed-token limit differs", err)
	}
	if _, err := tokens.AccessPortalPackage(t.Context(), secret, packageapp.PortalAcceptanceInput{}, false); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("revoked token accesses", err)
	}
}

func TestPostgresPortalFailureAtomicity(t *testing.T) {
	for _, operation := range []string{"create", "access", "revoke"} {
		for _, stage := range []string{"write", "audit", "commit"} {
			t.Run(operation+"-"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedSummaryMetadata(t, p)
				writes, err := BuildPortalAccessCommands(store, "portal-test-pepper", true)
				if err != nil {
					t.Fatal(err)
				}
				tokens, err := BuildPortalTokenCommands(store, store, "portal-test-pepper", true)
				if err != nil {
					t.Fatal(err)
				}
				a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
				in := packageapp.CreatePortalAccessInput{PackageID: "package", CustomerName: "Customer", RequireNDA: true, ExpiresAt: time.Now().Add(time.Hour)}
				var id, secret string
				if operation != "create" {
					v, s, err := writes.CreatePortalAccess(t.Context(), a, in)
					if err != nil {
						t.Fatal(err)
					}
					id, secret = v.ID, s
				}
				before := portalWiringCounts(t, p)
				table, event := "customer_portal_access", "INSERT"
				if operation != "create" {
					event = "UPDATE"
				}
				if stage == "audit" {
					table, event = "audit_chain_entries", "INSERT"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_portal BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_portal()", event, table)
				if stage == "commit" {
					trigger = fmt.Sprintf("CREATE CONSTRAINT TRIGGER reject_portal AFTER %s ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_portal()", event, table)
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_portal()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private portal database';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "create":
					v, s, e := writes.CreatePortalAccess(t.Context(), a, in)
					err = e
					if v.ID != "" || s != "" {
						t.Fatal("failed issuance published secret")
					}
				case "access":
					v, e := tokens.AccessPortalPackage(t.Context(), secret, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false)
					err = e
					if v.ID != "" {
						t.Fatal("failed access published package")
					}
				case "revoke":
					v, e := writes.RevokePortalAccess(t.Context(), a, id)
					err = e
					if v.ID != "" {
						t.Fatal("failed revoke published result")
					}
				}
				if err == nil || portalWiringCounts(t, p) != before {
					t.Fatal("late portal failure committed effects")
				}
				if id != "" {
					var mutated bool
					if err := p.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL OR access_count<>0 OR nda_accepted_at IS NOT NULL FROM customer_portal_access WHERE id=$1`, id).Scan(&mutated); err != nil || mutated {
						t.Fatal("failed lifecycle changed row", err)
					}
				}
			})
		}
	}
}

func TestPostgresPortalLocksCurrentParentsAndBoundsTokenLookup(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	writes, err := BuildPortalAccessCommands(store, "portal-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	in := packageapp.CreatePortalAccessInput{PackageID: "package", CustomerName: "Customer", ExpiresAt: time.Now().Add(time.Hour)}
	var accessID string
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(t.Context(), a, "POST", "/v1/customer-portal/access", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, _, err := writes.CreatePortalAccess(ctx, a, in)
		if err != nil {
			return 0, nil, err
		}
		accessID = v.ID
		for _, row := range []struct{ table, id string }{{"tenants", "tenant"}, {"products", "product"}, {"releases", "release"}, {"customer_security_packages", "package"}} {
			other, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = other.Exec(ctx, `SELECT id FROM `+row.table+` WHERE id=$1 FOR UPDATE NOWAIT`, row.id)
			_ = other.Rollback(context.WithoutCancel(ctx))
			var locked *pgconn.PgError
			if !errors.As(err, &locked) || locked.Code != "55P03" {
				t.Fatal("portal parent unlocked before commit", row.table, err)
			}
		}
		return 201, map[string]any{"id": v.ID}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Index rollback/reapplication preserves existing credential rows.
	if _, err := p.Exec(t.Context(), `DROP INDEX customer_portal_access_prefix_lookup_idx;CREATE INDEX customer_portal_access_prefix_lookup_idx ON customer_portal_access(prefix,tenant_id,id)`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM customer_portal_access`).Scan(&count); err != nil || count != 1 {
		t.Fatal("lookup index changed credential rows", err)
	}
	// Revocation must not transfer or require the stored private token hash.
	if _, err := p.Exec(t.Context(), `UPDATE customer_portal_access SET hash=repeat('x',9437184) WHERE id=$1`, accessID); err != nil {
		t.Fatal(err)
	}
	if v, err := writes.RevokePortalAccess(t.Context(), a, accessID); err != nil || v.RevokedAt == nil || v.Hash != "" {
		t.Fatal("administrative revocation loaded private hash", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE customer_security_packages SET tenant_id='other',product_id='other-product',release_id=NULL WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	if err := writes.AuthorizeRevokePortalAccess(t.Context(), a, accessID); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("revocation replay ignored changed package owner", err)
	}
	var prefix string
	if err := p.QueryRow(t.Context(), `SELECT prefix FROM customer_portal_access WHERE id=$1`, accessID).Scan(&prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO customer_portal_access(id,tenant_id,package_id,customer_name,prefix,hash,expires_at,schema_version,created_at)VALUES('collision','other','package','Other',$1,'hash',now()+interval '1 hour','portal.v1',now())`, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupPortalAccess(t.Context(), prefix); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("ambiguous credential prefix did not fail closed", err)
	}
}
