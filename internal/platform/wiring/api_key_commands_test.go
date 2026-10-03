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

func TestPostgresAPIKeyHTTPUsesFocusedWritesAndPrivateRestartReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Keys'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	for _, pepper := range []string{"", " ", identityapp.LocalDevelopmentPepper} {
		if c, err := BuildAPIKeyCommands(store, pepper, true); !errors.Is(err, identityapp.ErrValidation) || c != nil {
			t.Fatal("unsafe production credentials accepted", err)
		}
	}
	if c, err := BuildAPIKeyCommands(nil, "key-test-pepper", true); err == nil || c != nil {
		t.Fatal("missing credential transaction accepted")
	}
	auth := &attestationHTTPActor{actor: domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}}
	request := func(key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "key-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.APIKeyCommands == nil {
			t.Fatal("credential issuance remains Ledger-backed", err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/api-keys", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private key storage") {
			t.Fatal("credential request status or persistence contract changed", w.Code, noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("credential error lacks Problem Details")
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
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM api_keys),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := `{"name":"Automation","scopes":["evidence:read","","evidence:read","custom:scope"]}`
	first := request("key", body, 201)
	secret, ok := first["secret"].(string)
	if !ok || secret == "" {
		t.Fatal("initial issuance omitted one-time credential")
	}
	metadata := first["api_key"].(map[string]any)
	var hash, prefix, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT hash,prefix FROM api_keys WHERE id=$1`, metadata["id"]).Scan(&hash, &prefix); err != nil {
		t.Fatal(err)
	}
	credential, err := identityapp.NewHMACAuthenticationCredentials("key-test-pepper")
	if err != nil || credential.Hash(secret) != hash || credential.Prefix(secret) != prefix || hash == secret {
		t.Fatal("issued key incompatible or raw", err)
	}
	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, metadata["id"]).Scan(&actorType, &actorID); err != nil || actorType != "human_user" || actorID != "human" {
		t.Fatal("key issuance audit incorrect", err)
	}
	if counts() != [3]int{1, 1, 1} {
		t.Fatal("issuance effects not atomic")
	}
	delete(first, "secret")
	if replay := request("key", body, 201); !reflect.DeepEqual(replay, first) || counts() != [3]int{1, 1, 1} {
		t.Fatal("restart replay lost public metadata or repeated credential issuance")
	}
	var saved string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='key'`).Scan(&saved); err != nil || strings.Contains(saved, secret) || strings.Contains(saved, hash) || strings.Contains(saved, `"secret"`) || strings.Contains(saved, `"hash"`) {
		t.Fatal("stored replay retained private credential", err)
	}
	request("key", strings.Replace(body, "Automation", "Changed", 1), 409)
	auth.actor.ResourceGrants = nil
	request("key", body, 403)
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}
	request("key", body, 403)
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}
	request("key", body, 403)
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}
	request("escalation", `{"name":"Instance","scopes":[" instance:admin "]}`, 403)
	if counts() != [3]int{1, 1, 1} {
		t.Fatal("denied issuance produced effects")
	}
	auth.actor.TenantID = "other"
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"admin"}}}
	other := request("key", body, 201)
	if other["api_key"].(map[string]any)["tenant_id"] != "other" || counts() != [3]int{2, 2, 2} {
		t.Fatal("tenant replay isolation failed")
	}
	auth.actor.TenantID = "tenant"
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}
	authn, err := BuildAuthenticator(store, store, "key-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := authn.Authenticate(ctx, secret)
	if err != nil || bound.TenantID != "tenant" || bound.KeyID != metadata["id"] || bound.CollectorID != "" || !reflect.DeepEqual(bound.Scopes, []string{"", "custom:scope", "evidence:read", "evidence:read"}) {
		t.Fatal("committed key did not authenticate correctly", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1`, metadata["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := authn.Authenticate(ctx, secret); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("revoked key retained authority", err)
	}
	// Historical unrelated credential metadata must never be transferred into
	// a command. Key names are not a unique identity; past expiry is supported
	// for compatibility but must never authenticate.
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET name=repeat('x',9437184) WHERE tenant_id='other'`); err != nil {
		t.Fatal(err)
	}
	expiredBody := `{"name":"Automation","scopes":["evidence:read"],"expires_at":"2020-01-01T00:00:00Z"}`
	expired := request("expired-key", expiredBody, 201)
	if _, err := authn.Authenticate(ctx, expired["secret"].(string)); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("expired issued key authenticated", err)
	}
	delete(expired, "secret")
	if replay := request("expired-key", expiredBody, 201); !reflect.DeepEqual(replay, expired) || counts() != [3]int{3, 3, 3} {
		t.Fatal("expired key replay or duplicate-name compatibility changed")
	}
	for _, stage := range []string{"api_keys", "audit_chain_entries", "idempotency_records", "commit"} {
		before := counts()
		var setup, teardown string
		switch stage {
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_key_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private key storage failure';END$$;CREATE CONSTRAINT TRIGGER reject_key_commit AFTER INSERT ON api_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_key_commit()`
			teardown = `DROP TRIGGER reject_key_commit ON api_keys`
		case "idempotency_records":
			setup = `CREATE OR REPLACE FUNCTION reject_key_replay()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private key storage failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_key_replay BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_key_replay()`
			teardown = `DROP TRIGGER reject_key_replay ON idempotency_records`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_key_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private key storage failure';END$$;CREATE TRIGGER reject_key_write BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_key_write()`
			teardown = `DROP TRIGGER reject_key_write ON ` + stage
		}
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		request("failure-"+stage, body, 500)
		if counts() != before {
			t.Fatal("failed issuance left credential or audit effects", stage)
		}
		var unsafe int
		// Repository Fail stores JSON null, not SQL NULL.
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, "failure-"+stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed issuance retained credential replay", err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		if stage == "idempotency_records" || stage == "commit" {
			request("failure-"+stage, body, 201)
			for i := range before {
				before[i]++
			}
		} else {
			request("failure-"+stage, body, 409)
		}
		if counts() != before {
			t.Fatal("failure retry violated credential transaction contract", stage)
		}
	}
}
