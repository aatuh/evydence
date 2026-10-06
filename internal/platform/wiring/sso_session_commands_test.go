package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestPostgresSSOSessionHTTPIssuesCompatibleOneTimeSecretsAndCurrentReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for _, test := range []struct {
		pepper     string
		production bool
	}{{"", true}, {identityapp.LocalDevelopmentPepper, true}} {
		if c, err := BuildSSOSessionCommands(store, test.pepper, test.production); err == nil || c != nil {
			t.Fatal("unsafe session pepper accepted")
		}
	}
	if c, err := BuildSSOSessionCommands(nil, "fixture-pepper", false); err == nil || c != nil {
		t.Fatal("missing session transactions accepted")
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO tenants(id,name)VALUES('tenant','Sessions'),('other','Other');
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES
('user','tenant','person@example.test',repeat('x',9437184),'active','human-user.v1',now()),
('operator','tenant','operator@example.test','Operator','active','human-user.v1',now()),
('other-user','other','other@example.test','Other','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,jwks)VALUES
('provider','tenant',repeat('x',9437184),'oidc','https://issuer.example.test','client','active','sso-provider.v1',now(),jsonb_build_object('unrelated',repeat('x',9437184))),
('operator-provider','tenant','Operator','oidc','https://operator.example.test','client','active','sso-provider.v1',now(),'{}'),
('other-provider','other','Other','saml','https://other.example.test','client','active','sso-provider.v1',now(),'{}');
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES
('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now()),
('target-grant','tenant','user','user','security_engineer','tenant','tenant','role-binding.v1',now())`); err != nil {
		t.Fatal(err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("session-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const operatorSecret = "evysso_session_operator_fixture"
	if _, err := pool.Exec(ctx, `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('operator-session','tenant','operator','operator-provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(operatorSecret), credentials.Hash(operatorSecret)); err != nil {
		t.Fatal(err)
	}
	request := func(key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "session-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SSOSessionCommands == nil {
			t.Fatal("session issuance remains Ledger-backed", err)
		}
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/sso/sessions", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+operatorSecret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), operatorSecret) || len(w.Body.Bytes()) > 32768 {
			t.Fatal("session response/persistence/cookie policy changed", w.Code, want, noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("session error lacks Problem Details")
			}
			return nil
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	expiry := time.Now().Add(30 * 24 * time.Hour).UTC()
	bytes, err := json.Marshal(map[string]any{"user_id": " user ", "provider_id": " provider ", "expires_at": expiry})
	if err != nil {
		t.Fatal(err)
	}
	body := string(bytes)
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_sessions),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	first := request("session", body, 201)
	session := first["session"].(map[string]any)
	secret := first["secret"].(string)
	parsedExpiry, err := time.Parse(time.RFC3339Nano, session["expires_at"].(string))
	if err != nil || parsedExpiry != expiry.Truncate(time.Microsecond) || session["user_id"] != "user" || session["provider_id"] != "provider" || session["schema_version"] != domain.SSOSessionSchemaVersion || len(secret) != 50 || !strings.HasPrefix(secret, "evysso_") || session["prefix"] != credentials.Prefix(secret) || session["hash"] != nil {
		t.Fatal("session issuance compatibility lost", err)
	}
	before := counts()
	replay := request("session", body, 201)
	if replay["secret"] != nil || !reflect.DeepEqual(session, replay["session"]) || counts() != before {
		t.Fatal("restart session replay reminted/disclosed credential or changed metadata")
	}
	authn, err := BuildAuthenticator(store, store, "session-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := authn.Authenticate(ctx, secret)
	if err != nil || actor.UserID != "user" || actor.SessionID != session["id"] || !actor.HasScope("evidence:read") || actor.HasScope("identity:admin") || actor.HasExplicitScope("instance:admin") {
		t.Fatal("new secret cannot authenticate or invented grants", err)
	}
	var hash, saved, action, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT hash FROM sso_sessions WHERE id=$1`, session["id"]).Scan(&hash); err != nil || hash != credentials.Hash(secret) || hash == secret {
		t.Fatal("session hash storage incompatible", err)
	}
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='session'`).Scan(&saved); err != nil || strings.Contains(saved, secret) || strings.Contains(saved, hash) || strings.Contains(saved, "unrelated") || strings.Contains(saved, `"secret"`) {
		t.Fatal("saved session replay contains credential material", err)
	}
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_type,actor_id FROM audit_chain_entries ORDER BY sequence LIMIT 1`).Scan(&action, &actorType, &actorID); err != nil || action != "sso_session.created" || actorType != "human_user" || actorID != "operator" {
		t.Fatal("session audit attribution changed", err)
	}
	request("session", strings.Replace(body, " user ", "operator", 1), 409)
	for i, bad := range []string{`{}`, `null`, strings.Replace(body, " user ", `user\u0000`, 1), strings.Replace(body, `"expires_at":`, `"expires_at":null,"ignored":`, 1), `{"user_id":"user","provider_id":"provider","expires_at":"not-date"}`} {
		request(fmt.Sprintf("bad-session-%d", i), bad, 400)
	}
	for i, foreign := range []string{strings.Replace(body, " user ", "other-user", 1), strings.Replace(body, " provider ", "other-provider", 1)} {
		request(fmt.Sprintf("foreign-session-%d", i), foreign, 404)
	}
	if counts() != before {
		t.Fatal("denied session request produced effects")
	}
	exec := func(query string) {
		t.Helper()
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []struct {
		mutate, restore string
		want            int
	}{
		{`UPDATE human_users SET tenant_id='other' WHERE id='user'`, `UPDATE human_users SET tenant_id='tenant' WHERE id='user'`, 404},
		{`UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='user'`, `UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='user'`, 404},
		{`UPDATE sso_providers SET tenant_id='other' WHERE id='provider'`, `UPDATE sso_providers SET tenant_id='tenant' WHERE id='provider'`, 404},
		{`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`, 403},
		{`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`, `UPDATE role_bindings SET role='tenant_admin' WHERE id='operator-grant'`, 403},
		{`UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`, `UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`, 401},
	} {
		exec(change.mutate)
		request("session", body, change.want)
		exec(change.restore)
	}
	if counts() != before {
		t.Fatal("current parent/authority denial changed session effects")
	}
	if replay := request("session", body, 201); replay["secret"] != nil || !reflect.DeepEqual(session, replay["session"]) {
		t.Fatal("restored authority changed session replay")
	}
	// Revoked/expired secrets stay unusable; replay is original metadata only.
	if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=now() WHERE id=$1`, session["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := authn.Authenticate(ctx, secret); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("revoked new session remains usable", err)
	}
	request("session", body, 201)
	if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET revoked_at=NULL,expires_at=now()-interval '1 hour' WHERE id=$1`, session["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := authn.Authenticate(ctx, secret); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("expired new session remains usable", err)
	}
	request("session", body, 201)
	// Provider activation is not a new administrative issuance precondition.
	exec(`UPDATE sso_providers SET status='inactive' WHERE id='provider'`)
	second := request("second-session", body, 201)
	if second["secret"] == secret || second["session"].(map[string]any)["id"] == session["id"] {
		t.Fatal("new session key reused credential or record")
	}
}

func TestPostgresSSOSessionWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Sessions');INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('user','tenant','person@example.test','User','active','human-user.v1',now());INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Provider','oidc','https://issuer.example.test','client','active','sso-provider.v1',now())`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOSessionCommands(store, "session-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	in := identityapp.CreateSSOSessionInput{UserID: "user", ProviderID: "provider", ExpiresAt: time.Now().Add(time.Hour)}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeCreateSSOSession(ctx, a, in) }}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, secret, err := c.CreateSSOSession(ctx, a, in)
		return 201, map[string]any{"session": domain.SSOSession(v), "secret": secret}, err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_sessions),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"sso_sessions", "audit_chain_entries", "replay", "commit"} {
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_session_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private session storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_session_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_session_stage()`
			teardown = `DROP TRIGGER reject_session_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_session_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private session storage';END$$;CREATE CONSTRAINT TRIGGER reject_session_stage AFTER INSERT ON sso_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_session_stage()`
			teardown = `DROP TRIGGER reject_session_stage ON sso_sessions`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_session_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private session storage';END$$;CREATE TRIGGER reject_session_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_session_stage()`
			teardown = `DROP TRIGGER reject_session_stage ON ` + stage
		}
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if status, response, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions", stage, []byte(`{}`), run); err == nil || status != 0 || response != nil || counts() != before {
			t.Fatal("failed session left effects or response", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed session retained successful replay", err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions", stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 201 || response == nil {
				t.Fatal("rolled back session reservation cannot retry", stage, err)
			}
			for i := range before {
				before[i]++
			}
			_, replay, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions", stage, []byte(`{}`), run)
			if err != nil || replay.(map[string]any)["secret"] != nil {
				t.Fatal("session retry replay disclosed a secret", err)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed session reservation unexpectedly retried", stage, err)
		}
		if counts() != before {
			t.Fatal("session fault retry duplicated effects", stage)
		}
	}
	// No sleeps: database lock_timeout proves parent status/ownership stability
	// after the real durable executor guard and before insertion/actual commit.
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/sessions", "parent-locks", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		for _, query := range []string{`UPDATE human_users SET status='deactivated' WHERE id='user'`, `UPDATE sso_providers SET tenant_id='other' WHERE id='provider'`} {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err == nil {
				_, err = tx.Exec(ctx, query)
			}
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatal("session parent escaped command transaction", err)
			}
		}
		return run(ctx, repos)
	}); err != nil {
		t.Fatal(err)
	}
}
