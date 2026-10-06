package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func seedReleaseBundleHTTP(t *testing.T, p *pgxpool.Pool) ed25519.PublicKey {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant',repeat('private-product',600000),'product'),('alternate','tenant','Alternate','alternate'),('foreign','other','Foreign','foreign');INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft'),('foreign-release','other','foreign','1','draft')`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return public
}
func releaseBundleHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.ReleaseBundleCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native bundle wiring absent", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/release-bundles", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("bundle status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	return w.Body.String()
}
func releaseBundleHTTPCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var v [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM release_bundles),(SELECT count(*)FROM signatures),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresReleaseBundleHTTPNativeRestartReplayAndCurrentScope(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	public := seedReleaseBundleHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,object_key,mode,retention_days,status,schema_version,created_at) VALUES('policy','tenant','reviewer@example.test','tenants/tenant/','tenants/tenant/sample','compliance',365,'configured',$1,now())`, domain.ObjectRetentionPolicyVersion); err != nil {
		t.Fatal(err)
	}
	body := `{"release_id":"release"}`
	one := releaseBundleHTTP(t, store, "bundle", body, 201)
	two := releaseBundleHTTP(t, store, "bundle", body, 201)
	assertRetentionHTTPReplay(t, one, two)
	var response struct {
		Data domain.ReleaseBundle `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &response); err != nil {
		t.Fatal(err)
	}
	proofs := response.Data.Manifest["object_lock_proofs"].([]any)
	if len(proofs) != 1 || proofs[0].(map[string]any)["sample_object_key_configured"] != true || strings.Contains(one, "reviewer@example.test") || strings.Contains(one, "tenants/tenant/sample") {
		t.Fatal("public signed retention projection changed or leaked source fields")
	}
	var replay struct {
		Data domain.ReleaseBundle `json:"data"`
	}
	if err := json.Unmarshal([]byte(two), &replay); err != nil {
		t.Fatal(err)
	}
	replayHash, err := (packageCanonicalizer{}).HashPackageManifest(t.Context(), replay.Data.Manifest)
	if err != nil || replayHash != response.Data.ManifestHash {
		t.Fatal("replay manifest no longer matches its signed commitment", err)
	}
	var value, hash, subject, job string
	if err := p.QueryRow(t.Context(), `SELECT s.value,b.manifest_hash,a.subject_id,j.kind FROM release_bundles b JOIN signatures s ON s.subject_id=b.id JOIN audit_chain_entries a ON a.signature_ref=s.id JOIN outbox_jobs j ON j.subject_id=b.id WHERE b.id=$1`, response.Data.ID).Scan(&value, &hash, &subject, &job); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || !ed25519.Verify(public, []byte(hash), sig) || subject != response.Data.ID || hash != response.Data.ManifestHash || job != "sign_bundle" {
		t.Fatal("bundle signature/audit/job mismatch", err)
	}
	releaseBundleHTTP(t, store, "bundle", " "+body, 409)
	releaseBundleHTTP(t, store, "foreign", `{"release_id":"foreign-release"}`, 404)
	// Completed replay needs neither manifest metadata nor current signing bytes.
	if _, err := p.Exec(t.Context(), `UPDATE releases SET version=repeat('x',5000) WHERE id='release';UPDATE signing_keys SET status='revoked',encrypted_private_key=decode('00','hex') WHERE id='key'`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, releaseBundleHTTP(t, store, "bundle", body, 201))
	for _, change := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='alternate' WHERE id='grant'`, `UPDATE role_bindings SET resource_type='project',resource_id='missing' WHERE id='grant'`, `UPDATE role_bindings SET role='viewer',resource_type='tenant',resource_id='tenant' WHERE id='grant'`} {
		if _, err := p.Exec(t.Context(), change); err != nil {
			t.Fatal(err)
		}
		releaseBundleHTTP(t, store, "bundle", body, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin',resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, releaseBundleHTTP(t, store, "bundle", body, 201))
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='alternate' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	releaseBundleHTTP(t, store, "bundle", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='product' WHERE id='release';UPDATE products SET tenant_id='other' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	releaseBundleHTTP(t, store, "bundle", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant' WHERE id='product';UPDATE releases SET tenant_id='other' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	releaseBundleHTTP(t, store, "bundle", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE releases SET tenant_id='tenant' WHERE id='release';UPDATE sso_sessions SET revoked_at=now() WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	releaseBundleHTTP(t, store, "bundle", body, 401)
	if releaseBundleHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatal("bundle replay duplicated durable effects")
	}
}

func TestPostgresReleaseBundleHTTPAtomicFailuresRollbackAllEffects(t *testing.T) {
	for _, stage := range []string{"signature", "bundle", "audit", "job", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedReleaseBundleHTTP(t, p)
			table := map[string]string{"signature": "signatures", "bundle": "release_bundles", "audit": "audit_chain_entries", "job": "outbox_jobs", "replay": "idempotency_records", "commit": "release_bundles"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_bundle BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_bundle()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_bundle BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_bundle()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_bundle AFTER INSERT ON release_bundles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_bundle()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_bundle() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-bundle SQL password=secret';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := `{"release_id":"release"}`
			releaseBundleHTTP(t, store, "failed", body, 500)
			want := [6]int{}
			if stage != "replay" && stage != "commit" {
				want[5] = 1
			}
			if releaseBundleHTTPCounts(t, p) != want {
				t.Fatal("partial bundle effects published")
			}
			var leaked int
			if err := p.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb`).Scan(&leaked); err != nil || leaked != 0 {
				t.Fatal("failed bundle response published", err)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_bundle ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[5] > 0 {
				key = "fresh"
			}
			releaseBundleHTTP(t, store, key, body, 201)
			for i := 0; i < 5; i++ {
				want[i] = 1
			}
			if releaseBundleHTTPCounts(t, p) != want {
				t.Fatal("bundle retry did not recover atomically")
			}
		})
	}
}
