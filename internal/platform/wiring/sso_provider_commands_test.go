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

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresSSOProviderHTTPUsesCurrentAuthorityAndRestartReplayWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if c, err := BuildSSOProviderCommands(nil); err == nil || c != nil {
		t.Fatal("missing provider transactions accepted")
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Providers'),('other','Other');
INSERT INTO products(id,tenant_id,name,slug,created_at)VALUES('product','tenant',repeat('x',9437184),'product',now());
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('operator','tenant','operator@example.test','Operator','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Fixture','oidc','https://issuer.example.test','client','active','sso-provider.v1',now()),('unrelated','other',repeat('x',9437184),'oidc','https://other.example.test','client','active','sso-provider.v1',now());
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now())`)
	credentials, err := identityapp.NewHMACAuthenticationCredentials("provider-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evysso_provider_fixture"
	exec(`INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('session','tenant','operator','provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(secret), credentials.Hash(secret))
	request := func(key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "provider-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SSOProviderCommands == nil {
			t.Fatal("provider registration remains Ledger-backed", err)
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
		r := httptest.NewRequest("POST", "/v1/sso/providers", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "private-provider-canary") || len(w.Body.Bytes()) > 32768 {
			t.Fatal("unsafe provider response or Ledger reload", w.Code, noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("provider error lacks Problem Details")
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
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_providers),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	const body = `{"name":" Example ","type":"oidc","issuer":"https://issuer.example.test/tenant/","client_id":"client","groups_claim":"groups","role_mapping":{"maintainers":"tenant_admin","token-reviewers":"security_engineer","unknown":"future-role"},"jwks":{"client_secret":"private-provider-canary","keys":[{"kty":"OKP","kid":"fixture","crv":"Ed25519","x":"public-only","key_ops":["verify"]}]}}`
	first := request("provider-create", body, 201)
	before := counts()
	if first["name"] != "Example" || first["issuer"] != "https://issuer.example.test/tenant/" || first["tenant_id"] != "tenant" || first["schema_version"] != domain.SSOProviderSchemaVersion {
		t.Fatal("provider DTO contract changed")
	}
	if replay := request("provider-create", body, 201); !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restart replay changed provider or duplicated effects")
	}
	second := request("provider-create-again", body, 201)
	if first["id"] == second["id"] {
		t.Fatal("new-key duplicate registration was silently reused")
	}
	request("provider-create", strings.Replace(body, " Example ", "Other", 1), 409)
	minimal := `{"name":"Minimal","type":"saml","issuer":"https://saml.example.test/entity","client_id":"client"}`
	if p := request("provider-minimal", minimal, 201); p["type"] != "saml" {
		t.Fatal("optional trust material compatibility lost")
	}
	before = counts()
	for _, bad := range []string{`{}`, `{"tenant_id":"other"}`, strings.Replace(minimal, "https://saml.example.test/entity", "https://user:private-provider-canary@issuer.example.test", 1), strings.Replace(minimal, `"Minimal"`, `"bad\u0000"`, 1), strings.Replace(minimal, `"Minimal"`, `"Minimal","role_mapping":{"g":null}`, 1), strings.Replace(minimal, `"Minimal"`, `"Minimal","jwks":{"keys":[{"kty":"OKP","kid":"bad\u0000","crv":"Ed25519","x":"public-only"}]}`, 1)} {
		request("bad-provider", bad, 400)
	}
	if counts() != before {
		t.Fatal("invalid provider requests emitted effects")
	}
	// Seed the exact receipt shape an older implementation could retain. The
	// new guard must reject the private request even when success already exists.
	authn, err := BuildAuthenticator(store, store, "provider-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	privateBody := strings.Replace(body, `"x":"public-only"`, `"x":"public-only","d":"private-provider-canary"`, 1)
	legacy := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := legacy.WithBody(ctx, a, "POST", "/v1/sso/providers", "historical-private", []byte(privateBody), func(context.Context, app.Repositories) (int, any, error) {
		return 201, map[string]any{"jwks": map[string]any{"d": "private-provider-canary"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	before = counts()
	request("historical-private", privateBody, 400)
	if counts() != before {
		t.Fatal("private replay rejection changed retained records")
	}
	for _, query := range []string{`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`, `UPDATE role_bindings SET role='tenant_admin',resource_type='product',resource_id='product' WHERE id='operator-grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other' WHERE id='operator-grant'`, `UPDATE role_bindings SET tenant_id='other' WHERE id='operator-grant'`} {
		exec(query)
		request("provider-create", body, 403)
		request("unauthorized-new", minimal, 403)
	}
	exec(`UPDATE role_bindings SET tenant_id='tenant',role='tenant_admin',resource_type='tenant',resource_id='tenant' WHERE id='operator-grant';UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`)
	request("provider-create", body, 401)
	exec(`UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`)
	if replay := request("provider-create", body, 201); !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restored current authority changed replay")
	}
	var saved, action, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='provider-create'`).Scan(&saved); err != nil || strings.Contains(saved, "private-provider-canary") || strings.Contains(saved, secret) {
		t.Fatal("new provider receipt retained secrets", err)
	}
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, first["id"]).Scan(&action, &actorType, &actorID); err != nil || action != "sso_provider.created" || actorType != "human_user" || actorID != "operator" {
		t.Fatal("provider audit attribution lost", err)
	}
	c, err := BuildSSOProviderCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a = domain.Actor{TenantID: "missing", KeyID: "key", Scopes: []string{"identity:admin"}}
	if out, err := c.CreateSSOProvider(ctx, a, identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client"}); !errors.Is(err, identityapp.ErrNotFound) || out.ID != "" || counts() != before {
		t.Fatal("missing tenant provider creation produced effects", err)
	}
}

func TestPostgresSSOProviderWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Providers')`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOProviderCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	in := identityapp.CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client"}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeCreateSSOProvider(ctx, a, in) }}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateSSOProvider(ctx, a, in)
		return 201, domain.SSOProvider(v), err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sso_providers),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"sso_providers", "audit_chain_entries", "replay", "commit"} {
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private provider storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_provider_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private provider storage';END$$;CREATE CONSTRAINT TRIGGER reject_provider_stage AFTER INSERT ON sso_providers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON sso_providers`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_provider_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private provider storage';END$$;CREATE TRIGGER reject_provider_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_provider_stage()`
			teardown = `DROP TRIGGER reject_provider_stage ON ` + stage
		}
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run); err == nil || counts() != before {
			t.Fatal("provider failure left committed effects", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed provider write retained success", stage, err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 201 || response == nil {
				t.Fatal("rolled back provider reservation cannot retry", stage, err)
			}
			for i := range before {
				before[i]++
			}
			if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/providers", stage, []byte(`{}`), run); err != nil {
				t.Fatal("provider retry cannot replay", stage, err)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed provider reservation unexpectedly retried", stage, err)
		}
		if counts() != before {
			t.Fatal("provider retry duplicated effects", stage)
		}
	}
}
