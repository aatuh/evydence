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

func seedMarketplaceReferences(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSummaryMetadata(t, p)
	if _, err := p.Exec(t.Context(), `
INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,valid_from,version,provider)VALUES('market-key','tenant','kid','Ed25519','active',repeat('x',9437184),convert_to('private-key-canary','UTF8'),now(),1,'local_ed25519');
INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value)VALUES('signature','tenant','package','package','market-key','Ed25519',repeat('x',9437184)),('foreign-signature','other','package','package','market-key','Ed25519','foreign');
INSERT INTO sboms(id,tenant_id,evidence_id,format,spec_version,component_count,components)VALUES('sbom','tenant','b','cyclonedx','1.6',0,jsonb_build_object('private',repeat('x',9437184))),('foreign-sbom','other','foreign','cyclonedx','1.6',0,'[]');
INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,scanner,target_ref,summary,findings)VALUES('scan','tenant','b','test','target','{}',jsonb_build_object('private',repeat('x',9437184))),('foreign-scan','other','foreign','test','target','{}','[]')`); err != nil {
		t.Fatal(err)
	}
}
func marketplaceWiringCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var n [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM marketplace_collectors),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
		t.Fatal(err)
	}
	return n
}
func marketplaceWiringInput() experimentalapp.MarketplaceCollectorInput {
	return experimentalapp.MarketplaceCollectorInput{Name: " scanner ", Provider: " example ", Version: " 1 ", Publisher: " team ", ManifestHash: "sha256:" + strings.Repeat("A", 64), SignatureID: " signature ", SBOMID: " sbom ", ScanID: " scan "}
}
func TestPostgresMarketplaceCollectorCommandsOwnedMetadataAndAtomicWrites(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedMarketplaceReferences(t, p)
	c, err := BuildMarketplaceCollectorCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildMarketplaceCollectorCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"collector:admin"}}
	in := marketplaceWiringInput()
	if err := c.AuthorizeCreateMarketplaceCollector(t.Context(), a, in); err != nil || marketplaceWiringCounts(t, p) != [3]int{} {
		t.Fatal("guard writes or reads full metadata", err)
	}
	v, err := c.CreateMarketplaceCollector(t.Context(), a, in)
	if err != nil || v.Name != "scanner" || v.SignatureID != "signature" || v.ManifestHash != in.ManifestHash || v.State != "registered" || marketplaceWiringCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("registration differs", v, err)
	}
	var tenant, hash, actor, subject string
	if err := p.QueryRow(t.Context(), `SELECT m.tenant_id,a.payload_hash,a.actor_id,a.subject_type FROM marketplace_collectors m JOIN audit_chain_entries a ON a.subject_id=m.id AND a.tenant_id=m.tenant_id WHERE m.id=$1`, v.ID).Scan(&tenant, &hash, &actor, &subject); err != nil || tenant != a.TenantID || hash != in.ManifestHash || actor != a.KeyID || subject != "marketplace_collector" {
		t.Fatal("audit binding differs", err)
	}
	before := marketplaceWiringCounts(t, p)
	if out, err := c.CreateMarketplaceCollector(t.Context(), a, in); !errors.Is(err, experimentalapp.ErrConflict) || out.ID != "" || marketplaceWiringCounts(t, p) != before {
		t.Fatal("duplicate metadata did not roll back", out, err)
	}
	for _, mode := range []string{"signature", "sbom", "scan", "missing-tenant", "human-product", "anonymous"} {
		actor, request := a, in
		want := experimentalapp.ErrNotFound
		switch mode {
		case "signature":
			request.SignatureID = "foreign-signature"
		case "sbom":
			request.SBOMID = "foreign-sbom"
		case "scan":
			request.ScanID = "foreign-scan"
		case "missing-tenant":
			actor.TenantID = "missing"
		case "human-product":
			actor.KeyID, actor.UserID = "", "user"
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: actor.Scopes}}
			want = application.ErrForbidden
		case "anonymous":
			actor.KeyID = ""
			want = application.ErrUnauthorized
		}
		if out, err := c.CreateMarketplaceCollector(t.Context(), actor, request); !errors.Is(err, want) || out.ID != "" || marketplaceWiringCounts(t, p) != before {
			t.Fatal("invalid reference crossed boundary", mode, out, err)
		}
	}
	for _, stage := range []string{"marketplace_collectors", "audit_chain_entries", "commit"} {
		target := stage
		sql := `CREATE OR REPLACE FUNCTION reject_marketplace_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private marketplace storage';END$$;`
		if stage == "commit" {
			target = "marketplace_collectors"
			sql += `CREATE CONSTRAINT TRIGGER reject_marketplace_write AFTER INSERT ON marketplace_collectors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_marketplace_write()`
		} else {
			sql += `CREATE TRIGGER reject_marketplace_write BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_marketplace_write()`
		}
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		request := in
		request.Version = "2"
		if out, err := c.CreateMarketplaceCollector(t.Context(), a, request); err == nil || out.ID != "" || marketplaceWiringCounts(t, p) != before {
			t.Fatal("failed write published partial effects", stage, out, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_marketplace_write ON `+target); err != nil {
			t.Fatal(err)
		}
	}
	in.Version, in.SignatureID, in.SBOMID, in.ScanID = "metadata-only", "", "", ""
	if out, err := c.CreateMarketplaceCollector(t.Context(), a, in); err != nil || out.SignatureID != "" || len(out.Limitations) != 1 || marketplaceWiringCounts(t, p) != [3]int{2, 2, 0} {
		t.Fatal("optional references became mandatory", out, err)
	}
}
func TestPostgresMarketplaceCollectorHTTPRestartReplayAndCurrentHumanAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedMarketplaceReferences(t, p)
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.MarketplaceCollectorCommands == nil {
			t.Fatal("registration remains Ledger-backed", err)
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
		r := httptest.NewRequest("POST", "/v1/marketplace-collectors", strings.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-key-canary") || strings.Contains(w.Body.String(), "evysso_receipt_fixture") {
			t.Fatal("unsafe or legacy response", w.Code, want, noReload.loads, w.Body.String())
		}
		return w.Body.Bytes()
	}
	const body = `{"name":"scanner","provider":"example","version":"1","publisher":"team","manifest_hash":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature_id":"signature","sbom_id":"sbom","scan_id":"scan"}`
	first := request("collector", body, 201)
	before := marketplaceWiringCounts(t, p)
	var original, replay any
	if json.Unmarshal(first, &original) != nil || json.Unmarshal(request("collector", body, 201), &replay) != nil || !reflect.DeepEqual(original, replay) || before != [3]int{1, 1, 1} || marketplaceWiringCounts(t, p) != before {
		t.Fatal("restart replay regenerated collector")
	}
	request("collector", strings.Replace(body, "scanner", "changed", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("collector", body, 403)
	request("denied", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_marketplace_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private marketplace commit';END$$;CREATE CONSTRAINT TRIGGER reject_marketplace_commit AFTER INSERT ON marketplace_collectors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_marketplace_commit()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit", strings.Replace(body, `"version":"1"`, `"version":"2"`, 1), 500)
	if strings.Contains(string(failed), "private marketplace commit") || strings.Contains(string(failed), `"state":"registered"`) || marketplaceWiringCounts(t, p) != before {
		t.Fatal("failed commit published success or partial effects")
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM sboms WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	request("collector", body, 404)
	if marketplaceWiringCounts(t, p) != before {
		t.Fatal("replay guard changed durable state")
	}
}
func TestPostgresMarketplaceCollectorReferenceLocksAndWorkerFenceSurviveOuterCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedMarketplaceReferences(t, p)
	c, err := BuildMarketplaceCollectorCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"collector:admin"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/marketplace-collectors", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateMarketplaceCollector(ctx, a, marketplaceWiringInput())
		if err != nil {
			return 0, nil, err
		}
		for _, query := range []string{`SELECT 1 FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT 1 FROM signatures WHERE id='signature' FOR UPDATE NOWAIT`, `SELECT 1 FROM sboms WHERE id='sbom' FOR UPDATE NOWAIT`, `SELECT 1 FROM vulnerability_scans WHERE id='scan' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, query)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("reference lock missing before outer commit")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT 1 FROM evidence_items WHERE id='outside' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, errors.New("unrelated evidence locked")
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
			return 0, nil, errors.New("worker projection fence missing")
		}
		return 201, v, nil
	})
	if err != nil || marketplaceWiringCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("outer transaction lost atomic locks", err)
	}
}
