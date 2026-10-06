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
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func saasWiringCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var n [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM saas_edition_profiles),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
		t.Fatal(err)
	}
	return n
}
func seedSaaSTenants(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant',repeat('x',9437184)),('admin','Admin'),('outside','Outside')`); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresSaaSProfileCommandsOwnedRecordGlobalAdminReferenceAndAtomicWrites(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSaaSTenants(t, p)
	c, err := BuildSaaSProfileCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSaaSProfileCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"instance:admin"}}
	in := experimentalapp.SaaSProfileInput{Name: " hosted ", Region: " eu ", AdminTenantID: " admin ", IsolationModel: " shared "}
	v, err := c.CreateSaaSProfile(t.Context(), a, in)
	wantHash, _ := application.NormalizedJSONHash(map[string]any{"Name": in.Name, "Region": in.Region, "AdminTenantID": in.AdminTenantID, "IsolationModel": in.IsolationModel})
	if err != nil || v.ConfigHash != wantHash || v.AdminTenantID != "admin" || v.TenantID != "tenant" || v.Name != "hosted" || saasWiringCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("profile semantics differ", v, err)
	}
	var hash, admin, tenant, auditHash string
	if err := p.QueryRow(t.Context(), `SELECT p.config_hash,p.admin_tenant_id,p.tenant_id,a.payload_hash FROM saas_edition_profiles p JOIN audit_chain_entries a ON a.subject_id=p.id WHERE p.id=$1`, v.ID).Scan(&hash, &admin, &tenant, &auditHash); err != nil || hash != wantHash || auditHash != hash || admin != "admin" || tenant != "tenant" {
		t.Fatal("durable bindings differ", err)
	}
	before := saasWiringCounts(t, p)
	for _, mode := range []string{"wildcard", "admin", "anonymous", "missing-admin", "missing-tenant"} {
		actor, request := a, in
		want := application.ErrForbidden
		switch mode {
		case "wildcard":
			actor.Scopes = []string{"*"}
		case "admin":
			actor.Scopes = []string{"admin"}
		case "anonymous":
			actor.KeyID = ""
			want = application.ErrUnauthorized
		case "missing-admin":
			request.AdminTenantID = "missing"
			want = experimentalapp.ErrNotFound
		case "missing-tenant":
			actor.TenantID = "missing"
			want = experimentalapp.ErrNotFound
		}
		if out, err := c.CreateSaaSProfile(t.Context(), actor, request); !errors.Is(err, want) || out.ID != "" || saasWiringCounts(t, p) != before {
			t.Fatal("invalid profile crossed instance boundary", mode, out, err)
		}
	}
	for _, stage := range []string{"saas_edition_profiles", "audit_chain_entries", "commit"} {
		target := stage
		sql := `CREATE OR REPLACE FUNCTION reject_saas_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SaaS failure';END$$;`
		if stage == "commit" {
			target = "saas_edition_profiles"
			sql += `CREATE CONSTRAINT TRIGGER reject_saas_write AFTER INSERT ON saas_edition_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_saas_write()`
		} else {
			sql += `CREATE TRIGGER reject_saas_write BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_saas_write()`
		}
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		if out, err := c.CreateSaaSProfile(t.Context(), a, in); err == nil || out.ID != "" || saasWiringCounts(t, p) != before {
			t.Fatal("failed profile write published partial effects", stage, out, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_saas_write ON `+target); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPostgresSaaSProfileHTTPRestartReplayCurrentIssuedScopeAndTenantExistence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSaaSTenants(t, p)
	credentials, err := identityapp.NewHMACAuthenticationCredentials("saas-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evy_saas_operator_fixture"
	if _, err := p.Exec(t.Context(), `INSERT INTO api_keys(id,tenant_id,name,prefix,hash,scopes,created_at)VALUES('operator','tenant','Operator',$1,$2,'["instance:admin"]',now())`, credentials.Prefix(secret), credentials.Hash(secret)); err != nil {
		t.Fatal(err)
	}
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "saas-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SaaSProfileCommands == nil {
			t.Fatal("profile remains Ledger-backed", err)
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
		r := httptest.NewRequest("POST", "/v1/saas/profiles", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 {
			t.Fatal("profile HTTP response or Ledger refresh differs", w.Code, want, noReload.loads, w.Body.String())
		}
		return w.Body.Bytes()
	}
	const body = `{"name":" hosted ","region":" eu ","admin_tenant_id":"admin","isolation_model":"shared"}`
	first := request("profile", body, 201)
	before := saasWiringCounts(t, p)
	var original, replay any
	if err := json.Unmarshal(first, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request("profile", body, 201), &replay); err != nil || !reflect.DeepEqual(original, replay) || saasWiringCounts(t, p) != before {
		t.Fatal("restart replay regenerated profile", err)
	}
	request("profile", strings.Replace(body, "hosted", "changed", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE api_keys SET scopes='["*"]' WHERE id='operator'`); err != nil {
		t.Fatal(err)
	}
	request("profile", body, 403)
	request("denied", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE api_keys SET scopes='["instance:admin"]' WHERE id='operator'`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_saas_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SaaS commit';END$$;CREATE CONSTRAINT TRIGGER reject_saas_commit AFTER INSERT ON saas_edition_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_saas_commit()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit", body, 500)
	if strings.Contains(string(failed), "private SaaS commit") || strings.Contains(string(failed), `"status":"proposed"`) || saasWiringCounts(t, p) != before {
		t.Fatal("HTTP failure published profile or partial state")
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM tenants WHERE id='admin'`); err != nil {
		t.Fatal(err)
	}
	request("profile", body, 404)
	if saasWiringCounts(t, p) != before {
		t.Fatal("replay guards wrote metadata")
	}
}
func TestPostgresSaaSProfileHoldsBothTenantKeysAndWorkerFenceThroughCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSaaSTenants(t, p)
	c, err := BuildSaaSProfileCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"instance:admin"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/saas/profiles", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateSaaSProfile(ctx, a, experimentalapp.SaaSProfileInput{Name: "Profile", Region: "eu", AdminTenantID: "admin", IsolationModel: "shared"})
		if err != nil {
			return 0, nil, err
		}
		for _, id := range []string{"tenant", "admin"} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE NOWAIT`, id)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("tenant key lock missing")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id='outside' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, errors.New("unrelated tenant locked")
		}
		// An opposite-direction profile writer may fence admin and key-share
		// both roots concurrently. Neither non-key writer lock needs upgrading.
		tx, err = p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := coordination.LockWorkerProjection(ctx, tx, "admin"); err != nil {
			_ = tx.Rollback(ctx)
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT id FROM tenants WHERE id='admin' FOR NO KEY UPDATE NOWAIT`)
		if err == nil {
			_, err = tx.Exec(ctx, `SELECT id FROM tenants WHERE id=ANY(ARRAY['admin','tenant']) ORDER BY id FOR KEY SHARE NOWAIT`)
		}
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, errors.New("opposite-direction admin reference conflicts with tenant key locks")
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
			return 0, nil, errors.New("profile projection fence missing")
		}
		return 201, v, nil
	})
	if err != nil || saasWiringCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("outer commit released profile locks early", err)
	}
}
