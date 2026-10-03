package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresSSOSessionRevocationHTTPCurrentAuthorityReplayAndLogout(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if c, err := BuildSSOSessionRevocationCommands(nil); err == nil || c != nil {
		t.Fatal("missing revocation transactions accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Sessions'),('other','Other');
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES
('user','tenant','user@example.test',repeat('x',9437184),'active','human-user.v1',now()),('operator','tenant','operator@example.test','Operator','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,jwks)VALUES
('provider','tenant',repeat('x',9437184),'oidc','https://issuer.example.test','client','active','sso-provider.v1',now(),jsonb_build_object('unrelated',repeat('x',9437184))),
('operator-provider','tenant','Operator','oidc','https://operator.example.test','client','active','sso-provider.v1',now(),'{}');
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES
('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now()),('user-grant','tenant','user','user','security_engineer','tenant','tenant','role-binding.v1',now())`); err != nil {
		t.Fatal(err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("session-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"operator-session": "evysso_revocation_operator_fixture", "session": "evysso_revocation_target_fixture", "logout-session": "evysso_logout_target_fixture", "cookie-session": "evysso_cookie_target_fixture"}
	for id, secret := range secrets {
		user, provider := "user", "provider"
		if id == "operator-session" {
			user, provider = "operator", "operator-provider"
		}
		if _, err := pool.Exec(ctx, `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,groups,expires_at,schema_version,created_at)VALUES($1,'tenant',$2,$3,$4,$5,'["maintainers"]',now()+interval '1 hour','sso-session.v1.0.0',now())`, id, user, provider, credentials.Prefix(secret), credentials.Hash(secret)); err != nil {
			t.Fatal(err)
		}
	}
	secrets["api-key"] = "evy_revocation_api_fixture"
	if _, err := pool.Exec(ctx, `INSERT INTO api_keys(id,tenant_id,name,prefix,hash,scopes,created_at)VALUES('key','tenant','Operator',$1,$2,'["*"]',now())`, credentials.Prefix(secrets["api-key"]), credentials.Hash(secrets["api-key"])); err != nil {
		t.Fatal(err)
	}
	request := func(path, key, secret, body, origin string, cookie bool, want int) (map[string]any, *httptest.ResponseRecorder) {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "session-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SSOSessionRevocationCommands == nil {
			t.Fatal("revocation remains Ledger-backed", err)
		}
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://example.com"+path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Idempotency-Key", key)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: "evydence_session", Value: secret})
		} else {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || len(w.Body.Bytes()) > 32768 {
			t.Fatal("revocation response or no-reload contract changed", w.Code, want, noReload.loads)
		}
		for _, value := range secrets {
			if strings.Contains(w.Body.String(), value) || strings.Contains(w.Body.String(), credentials.Hash(value)) {
				t.Fatal("revocation disclosed credential material")
			}
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("revocation error exposed/cleared cookie")
			}
			return nil, w
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data, w
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_sessions WHERE revoked_at IS NOT NULL),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec := func(q string) {
		t.Helper()
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	first, w := request("/v1/sso/sessions/session/revoke", "revoke", secrets["operator-session"], "{}", "", false, 200)
	if first["id"] != "session" || first["revoked_at"] == nil || first["hash"] != nil || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("admin revocation DTO/cookie policy changed")
	}
	before := counts()
	replay, _ := request("/v1/sso/sessions/session/revoke", "revoke", secrets["operator-session"], "{}", "", false, 200)
	if !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restart revocation replay changed metadata/effects")
	}
	request("/v1/sso/sessions/session/revoke", "revoke", secrets["operator-session"], "", "", false, 409)
	request("/v1/sso/sessions/session/revoke", "new-revoke", secrets["operator-session"], "{}", "", false, 409)
	authn, err := BuildAuthenticator(store, store, "session-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authn.Authenticate(ctx, secrets["session"]); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("revoked target credential remains usable", err)
	}
	for _, change := range []struct {
		mutate, restore string
		want            int
	}{
		{`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`, `UPDATE role_bindings SET role='tenant_admin' WHERE id='operator-grant'`, 403},
		{`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`, 403},
		{`UPDATE sso_sessions SET tenant_id='other' WHERE id='session'`, `UPDATE sso_sessions SET tenant_id='tenant' WHERE id='session'`, 404},
		{`UPDATE human_users SET status='deactivated' WHERE id='operator'`, `UPDATE human_users SET status='active' WHERE id='operator'`, 401},
	} {
		exec(change.mutate)
		request("/v1/sso/sessions/session/revoke", "revoke", secrets["operator-session"], "{}", "", false, change.want)
		exec(change.restore)
	}
	if counts() != before {
		t.Fatal("denied replay changed revocation effects")
	}
	request("/v1/sso/logout", "api-key", secrets["api-key"], "{}", "", false, 403)
	if counts() != before {
		t.Fatal("API key logout changed lifecycle/audit/replay")
	}
	// Logout requires no administration grant; its old credential then stops working.
	logout, w := request("/v1/sso/logout", "logout", secrets["logout-session"], "{}", "", false, 200)
	if logout["id"] != "logout-session" || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout lost self-only commit cookie clearing")
	}
	request("/v1/sso/logout", "logout", secrets["logout-session"], "{}", "", false, 401)
	request("/v1/sso/logout", "cross-origin", secrets["cookie-session"], "{}", "https://attacker.example", true, 403)
	request("/v1/sso/logout", "missing-origin", secrets["cookie-session"], "{}", "", true, 403)
	if _, err := authn.Authenticate(ctx, secrets["cookie-session"]); err != nil {
		t.Fatal("denied cookie request revoked session", err)
	}
	request("/v1/sso/logout", "cookie-logout", secrets["cookie-session"], "{}", "https://example.com", true, 200)
	if _, err := authn.Authenticate(ctx, secrets["cookie-session"]); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("cookie logout secret remains usable", err)
	}
	var actorID string
	if err := pool.QueryRow(ctx, `SELECT actor_id FROM audit_chain_entries WHERE subject_id='session'`).Scan(&actorID); err != nil || actorID != "operator" {
		t.Fatal("revocation audit caller lost", err)
	}
}

func TestPostgresSSOSessionRevocationFailuresAndLocks(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Sessions');INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,groups,expires_at,schema_version,created_at)VALUES('session','tenant','user','provider','public-prefix',repeat('x',9437184),'["maintainers"]',now()-interval '1 hour','sso-session.v1.0.0',now()-interval '2 hours')`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOSessionRevocationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeRevokeSSOSession(ctx, a, "session")
	}}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.RevokeSSOSession(ctx, a, "session")
		return 200, domain.SSOSession(v), err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_sessions WHERE revoked_at IS NOT NULL),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"write", "audit", "replay", "commit"} {
		var table, event, condition string
		switch stage {
		case "write":
			table, event = "sso_sessions", "BEFORE UPDATE"
		case "audit":
			table, event = "audit_chain_entries", "BEFORE INSERT"
		case "replay":
			table, event, condition = "idempotency_records", "BEFORE UPDATE", "IF NEW.state<>'completed' THEN RETURN NEW;END IF;"
		case "commit":
			table, event = "sso_sessions", "AFTER UPDATE"
		}
		trigger := "CREATE TRIGGER reject_revocation "
		if stage == "commit" {
			trigger = "CREATE CONSTRAINT TRIGGER reject_revocation "
		}
		deferrable := ""
		if stage == "commit" {
			deferrable = " DEFERRABLE INITIALLY DEFERRED"
		}
		setup := `CREATE OR REPLACE FUNCTION reject_revocation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN ` + condition + `RAISE EXCEPTION 'private revocation storage';END$$;` + trigger + event + ` ON ` + table + deferrable + ` FOR EACH ROW EXECUTE FUNCTION reject_revocation()`
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if status, out, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", stage, []byte(`{}`), run); err == nil || status != 0 || out != nil || counts() != before {
			t.Fatal("failed revocation retained effects/output", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE idempotency_key=$1 AND(status<>0 OR response<>'null'::jsonb)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed revocation retained successful receipt", err)
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_revocation ON `+table); err != nil {
			t.Fatal(err)
		}
		if stage == "write" || stage == "audit" {
			if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", stage, []byte(`{}`), run); !errors.Is(err, app.ErrIdempotencyFailed) {
				t.Fatal("failed command reservation unexpectedly retried", stage, err)
			}
		} else {
			status, out, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", stage, []byte(`{}`), run)
			if err != nil || status != 200 || out == nil {
				t.Fatal("rolled back reservation cannot retry", stage, err)
			}
			_, replay, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", stage, []byte(`{}`), run)
			if err != nil || replay == nil || counts() != ([3]int{before[0] + 1, before[1] + 1, before[2] + 1}) {
				t.Fatal("retried revocation replay duplicated effects", stage, err)
			}
			// Fixture-only reset makes the next fault exercise a fresh transition.
			if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=NULL WHERE id='session'`); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", "row-lock", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err == nil {
			_, err = tx.Exec(ctx, `UPDATE sso_sessions SET user_id='different' WHERE id='session'`)
		}
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatal("session owner escaped revocation transaction", err)
		}
		return run(ctx, repos)
	}); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT octet_length(hash) FROM sso_sessions WHERE id='session'`).Scan(&stored); err != nil || stored != 9437184 || counts() != ([3]int{1, 3, 3}) {
		t.Fatal("revocation loaded/replaced hash or left duplicate effects", err)
	}
	for i, bad := range []string{`jsonb_build_array(repeat('x',131073))`, `'{}'::jsonb`, `'[null]'::jsonb`} {
		if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET groups=`+bad+` WHERE id='session'`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions/session/revoke", fmt.Sprintf("oversized-%d", i), []byte(`{}`), run); !errors.Is(err, identityapp.ErrConflict) && !errors.Is(err, app.ErrConflict) {
			t.Fatal("invalid/oversized stored metadata was accepted", err)
		}
	}
}
