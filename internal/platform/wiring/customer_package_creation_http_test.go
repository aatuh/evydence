package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func seedCustomerCreationHTTP(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	for _, sql := range []string{
		`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product'),('sibling','tenant','Sibling','sibling'),('foreign','other','Foreign','foreign');
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('sibling-release','tenant','sibling','1','draft'),('foreign-release','other','foreign','1','draft');
INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('profile','tenant','Customer',ARRAY['sbom'],ARRAY['internal_notes','payload_ref','secret'],'redaction-profile.v1.0.0',now()),('foreign-profile','other','Foreign',ARRAY['sbom'],'{}','redaction-profile.v1.0.0',now());`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs,payload_ref,metadata)
VALUES('source','tenant','product','release','sbom','private-source-title','test',now(),'evidence.v1','sha256:source','sha256:source','json','L2','pending','[]','private-payload-location','{"secret":"private-evidence-secret"}'),('foreign-source','other','foreign','foreign-release','sbom','private-foreign-title','test',now(),'evidence.v1','sha256:foreign','sha256:foreign','json','L2','pending','[]','private-foreign-location','{}');
INSERT INTO sboms(id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components)VALUES('sbom','tenant','source','release','CycloneDX','1.6',1,'[{"name":"private-component-name","secret":"private-component-secret"}]'),('foreign-sbom','other','foreign-source','foreign-release','CycloneDX','1.6',0,'[]');`,
		`UPDATE tenants SET name=repeat('private-unrelated-tenant',400000) WHERE id='other';
UPDATE redaction_profiles SET name=repeat('private-unrelated-profile',400000) WHERE id='foreign-profile';`,
	} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return fmt.Sprintf(`{"product_id":"product","release_id":"release","redaction_profile_id":"profile","title":"Review","expires_at":%q}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
}

func customerCreationHTTPCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var v [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM customer_security_packages),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
		t.Fatal(err)
	}
	return v
}

func customerCreationHTTP(t *testing.T, store *postgres.Store, key, body string, want int, configure ...func(*httpapi.ServerOptions)) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.CustomerPackageCreationCommands == nil {
		t.Fatal("customer creation route remains Ledger-backed", err)
	}
	for _, fn := range configure {
		fn(&opts)
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
	r := httptest.NewRequest("POST", "/v1/customer-packages", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"manifest"`) {
		t.Fatalf("unsafe customer creation status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("replay key missing")
	}
	return w.Body.String()
}

func TestPostgresCustomerCreationHTTPExpiredOriginalReplayKeepsFrozenPolicy(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	body := seedCustomerCreationHTTP(t, p)
	now := time.Now().UTC().Truncate(time.Microsecond)
	configure := func(opts *httpapi.ServerOptions) {
		reader, err := postgres.NewCustomerPackageCreationSnapshotReader(store, verificationCanonicalHasher{}, localed25519.PayloadVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		opts.CustomerPackageCreationCommands, err = packageapp.NewCustomerPackageCommands(packageapp.CustomerPackageCommandConfig{Reader: reader, Transactions: customerPackageCreationTransactions{store}, Authorizer: packagequery.NewCustomerPackageCreationAuthorizer(), Hasher: packageCanonicalizer{}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(application.NewID)})
		if err != nil {
			t.Fatal(err)
		}
	}
	one := customerCreationHTTP(t, store, "expired-original", body, 201, configure)
	now = now.Add(2 * time.Hour)
	if _, err := p.Exec(t.Context(), `UPDATE products SET created_at='infinity'WHERE id='product';UPDATE redaction_profiles SET name='Changed policy',excluded_fields=ARRAY['spec_version']WHERE id='profile'`); err != nil {
		t.Fatal(err)
	}
	customerCreationJSONEqual(t, one, customerCreationHTTP(t, store, "expired-original", body, 201, configure))
	customerCreationHTTP(t, store, "new-expired", body, 400, configure)
	if customerCreationHTTPCounts(t, p) != [4]int{1, 1, 1, 1} {
		t.Fatal("expired replay rebuilt package or fresh creation bypassed expiry")
	}
}

func customerCreationJSONEqual(t *testing.T, a, b string) {
	t.Helper()
	var x, y any
	left, right := json.NewDecoder(strings.NewReader(a)), json.NewDecoder(strings.NewReader(b))
	left.UseNumber()
	right.UseNumber()
	if left.Decode(&x) != nil || right.Decode(&y) != nil || !reflect.DeepEqual(x, y) {
		t.Fatal("replay changed original public package")
	}
}

func TestPostgresCustomerCreationHTTPNativeSnapshotAndRestartReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	body := seedCustomerCreationHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest)VALUES('artifact','tenant','Artifact','application/octet-stream',9007199254740993,'sha256:artifact');UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact"}]'WHERE id='source';UPDATE sboms SET artifact_id='artifact'WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	one := customerCreationHTTP(t, store, "create", body, 201)
	var result struct {
		Data domain.CustomerSecurityPackage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewBufferString(one))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	v := result.Data
	if v.ID == "" || v.ProductID != "product" || v.ReleaseID != "release" || v.RedactionProfileID != "profile" || v.Title != "Review" || v.State != "generated" || v.AccessCount != 0 || v.CreatedAt.Nanosecond()%1000 != 0 || customerCreationHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
		t.Fatal("package/audit/replay not committed together", v.ID)
	}
	encoded, err := json.Marshal(v.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := application.NormalizedJSONHash(json.RawMessage(encoded))
	if err != nil || hash != v.ManifestHash {
		t.Fatal("public manifest hash differs", err)
	}
	for _, fragment := range []string{`"id":"sbom"`, `"evidence_ids":["source"]`, `"component_count":1`, `"size":9007199254740993`, `"readiness_summary"`, `"verification_material"`, `"redaction_profile"`} {
		if !strings.Contains(string(encoded), fragment) {
			t.Fatal("native public section absent", fragment, string(encoded))
		}
	}
	var storedHash, actor, typ, subject, receipt string
	if err := p.QueryRow(t.Context(), `SELECT c.manifest_hash,a.actor_id,a.entry_type,a.subject_id,i.response::text FROM customer_security_packages c JOIN audit_chain_entries a ON a.tenant_id=c.tenant_id AND a.subject_id=c.id JOIN idempotency_records i ON i.tenant_id=c.tenant_id AND i.idempotency_key='create' WHERE c.id=$1`, v.ID).Scan(&storedHash, &actor, &typ, &subject, &receipt); err != nil {
		t.Fatal(err)
	}
	if storedHash != hash || actor != "user" || typ != "customer_package.generated" || subject != v.ID || strings.Contains(receipt, "private-") {
		t.Fatal("durable public result/audit differs")
	}
	// Poison selected source metadata after commit. Restart replay must return
	// the frozen result, not rebuild a snapshot or load the tenant aggregate.
	if _, err := p.Exec(t.Context(), `UPDATE sboms SET spec_version='after';UPDATE products SET created_at='infinity'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	customerCreationJSONEqual(t, one, customerCreationHTTP(t, store, "create", body, 201))
	customerCreationHTTP(t, store, "create", strings.Replace(body, `"title":"Review"`, `"title":"Changed"`, 1), 409)
	if customerCreationHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
		t.Fatal("replay/conflict generated effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='sibling'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	customerCreationHTTP(t, store, "create", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='release'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	customerCreationJSONEqual(t, one, customerCreationHTTP(t, store, "create", body, 201))
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE releases SET product_id='sibling',version='moved'WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	customerCreationHTTP(t, store, "create", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='product',version='1'WHERE id='release';UPDATE redaction_profiles SET tenant_id='other'WHERE id='profile'`); err != nil {
		t.Fatal(err)
	}
	customerCreationHTTP(t, store, "create", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE redaction_profiles SET tenant_id='tenant'WHERE id='profile';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	customerCreationHTTP(t, store, "create", body, 401)
	if customerCreationHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
		t.Fatal("revoked authority mutated frozen package/audit/replay")
	}
}

func TestPostgresCustomerCreationHTTPRejectsForeignAndMalformedBeforeEffects(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	body := seedCustomerCreationHTTP(t, p)
	for i, tc := range []struct{ field, value string }{{"product_id", "foreign"}, {"release_id", "foreign-release"}, {"release_id", "sibling-release"}, {"redaction_profile_id", "foreign-profile"}, {"product_id", "missing"}} {
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) != nil {
			t.Fatal("fixture")
		}
		m[tc.field] = tc.value
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		customerCreationHTTP(t, store, fmt.Sprint("foreign-", i), string(b), 404)
	}
	for i, bad := range []string{`null`, strings.TrimSuffix(body, "}") + `,"title":null}`, strings.TrimSuffix(body, "}") + `,"TITLE":"Alias"}`, strings.TrimSuffix(body, "}") + `,"unknown":true}`, strings.Repeat(" ", 65537), strings.Replace(body, `"title":"Review"`, `"title":"`+strings.Repeat("é", 2049)+`"`, 1)} {
		customerCreationHTTP(t, store, fmt.Sprint("malformed-", i), bad, 400)
	}
	if customerCreationHTTPCounts(t, p) != [4]int{} {
		t.Fatal("invalid/foreign input generated effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE products SET created_at='infinity'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	customerCreationHTTP(t, store, "invalid-snapshot", body, 409)
	if customerCreationHTTPCounts(t, p) != [4]int{0, 0, 0, 1} {
		t.Fatal("invalid snapshot persisted package/audit/success replay")
	}
	var response []byte
	if err := p.QueryRow(t.Context(), `SELECT response FROM idempotency_records WHERE idempotency_key='invalid-snapshot'`).Scan(&response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "null" && string(response) != "{}" && len(response) != 0 {
		t.Fatal("safe failure tombstone retained a result", string(response))
	}
}

func TestPostgresCustomerCreationHTTPAtomicFailureAndRetry(t *testing.T) {
	for _, stage := range []string{"insert", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			body := seedCustomerCreationHTTP(t, p)
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_customer_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-customer-sql-secret';END$$`); err != nil {
				t.Fatal(err)
			}
			table := "customer_security_packages"
			if stage == "audit" {
				table = "audit_chain_entries"
			}
			if stage == "replay" {
				table = "idempotency_records"
			}
			trigger := "CREATE TRIGGER reject_customer_http BEFORE INSERT ON " + table + " FOR EACH ROW EXECUTE FUNCTION reject_customer_http()"
			if stage == "replay" {
				trigger = "CREATE TRIGGER reject_customer_http BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_customer_http()"
			}
			if stage == "commit" {
				trigger = "CREATE CONSTRAINT TRIGGER reject_customer_http AFTER INSERT ON customer_security_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_customer_http()"
			}
			if _, err := p.Exec(t.Context(), trigger); err != nil {
				t.Fatal(err)
			}
			customerCreationHTTP(t, store, "failed", body, 500)
			counts := customerCreationHTTPCounts(t, p)
			if counts[0] != 0 || counts[1] != 0 || counts[2] != 0 || counts[3] > 1 {
				t.Fatal("HTTP transaction failure persisted partial command", counts)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_customer_http ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if counts[3] != 0 {
				key = "retry-new-key"
			}
			customerCreationHTTP(t, store, key, body, 201)
			if customerCreationHTTPCounts(t, p) != [4]int{1, 1, 1, counts[3]} {
				t.Fatal("failed write could not safely retry")
			}
		})
	}
}
