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

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresSSOIdentityLinkAndExchangeUseSameMutationFenceOrder(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Identity');INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Provider','oidc','https://issuer.example.test','client','active','sso-provider.v1','2026-09-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	uow, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uow.Rollback(ctx) }()
	reader, ok := uow.Repositories().Identity.(identityapp.SSOIdentityLinkWriteReader)
	if !ok {
		t.Fatal("missing focused identity-link reader")
	}
	if err := reader.LockSSOIdentityLinkWrites(ctx, "tenant"); err != nil {
		t.Fatal(err)
	}
	exchange, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exchange.Rollback(ctx) }()
	if _, err := exchange.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	snapshot := app.SSOExchangeSnapshot{Provider: domain.SSOProvider{ID: "provider", TenantID: "tenant", Name: "Provider", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", RoleMapping: map[string]string{}, JWKS: map[string]any{}, SAMLSigningCertificates: []string{}, Status: "active", SchemaVersion: "sso-provider.v1", CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, Subject: "absent"}
	err = repositories.New(exchange).Identity.ValidateSSOExchangeState(ctx, snapshot)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatal("exchange acquired identity-table locks before waiting for the mutation fence", err)
	}
}

func TestPostgresSSOIdentityLinkHTTPChecksCurrentParentsAuthorityAndRestartReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if c, err := BuildSSOIdentityLinkCommands(nil); err == nil || c != nil {
		t.Fatal("missing identity link transactions accepted")
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO tenants(id,name)VALUES('tenant','Identity'),('other','Other');
INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES
('user','tenant','person@example.test',repeat('x',9437184),'deactivated','human-user.v1',now()),
('operator','tenant','operator@example.test','Operator','active','human-user.v1',now()),
('second-user','tenant','second@example.test','Second','active','human-user.v1',now()),
('other-user','other','other@example.test','Other','active','human-user.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,jwks)VALUES
('provider','tenant',repeat('x',9437184),'oidc','https://issuer.example.test','client','inactive','sso-provider.v1',now(),jsonb_build_object('unrelated',repeat('x',9437184))),
('operator-provider','tenant','Operator','oidc','https://operator.example.test','client','active','sso-provider.v1',now(),'{}'),
('other-provider','other','Other','saml','https://other.example.test','client','active','sso-provider.v1',now(),'{}');
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now())`); err != nil {
		t.Fatal(err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("identity-link-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evysso_identity_link_fixture"
	if _, err := pool.Exec(ctx, `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('operator-session','tenant','operator','operator-provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, credentials.Prefix(secret), credentials.Hash(secret)); err != nil {
		t.Fatal(err)
	}
	request := func(key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "identity-link-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SSOIdentityLinkCommands == nil {
			t.Fatal("identity linking remains Ledger-backed", err)
		}
		noReload := newAggregateLoadCanary(t, ctx, store)
		s, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/sso/identity-links", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(ctx) || strings.Contains(w.Body.String(), secret) || len(w.Body.Bytes()) > 32768 {
			t.Fatal("identity link response/bounded persistence changed", w.Code, want, noReload.Intact(ctx), w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("link error lacks Problem Details")
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
	body := `{"user_id":" user ","provider_id":" provider ","subject":" Subject-1 ","email":" PERSON@example.test ","verified":true}`
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM user_identity_links),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	first := request("link", body, 201)
	if first["user_id"] != "user" || first["provider_id"] != "provider" || first["subject"] != "Subject-1" || first["email"] != "person@example.test" || first["verified"] != true || first["schema_version"] != "user-identity-link.v1.0.0" {
		t.Fatal("link DTO contract changed")
	}
	before := counts()
	if replay := request("link", body, 201); !reflect.DeepEqual(first, replay) || counts() != before {
		t.Fatal("restart replay lost link metadata or duplicated effects")
	}
	request("link", strings.Replace(body, "Subject-1", "changed", 1), 409)
	// A distinct key cannot reassign or duplicate an existing provider subject.
	request("duplicate", body, 409)
	request("reassign", strings.Replace(strings.Replace(body, " user ", "second-user", 1), "PERSON@example.test", "second@example.test", 1), 409)
	var assignedUser string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM user_identity_links WHERE tenant_id='tenant' AND provider_id='provider' AND subject='Subject-1'`).Scan(&assignedUser); err != nil || assignedUser != "user" {
		t.Fatal("conflicting link reassigned identity", err)
	}
	for i, bad := range []string{`{}`, `null`, strings.Replace(body, `"verified":true`, `"verified":false`, 1), strings.Replace(body, `"verified":true`, `"verified":null`, 1), strings.Replace(body, "Subject-1", `subject\u0000`, 1), strings.Replace(body, `"verified":true`, `"verified":true,"verified":true`, 1), strings.Replace(body, `"email":" PERSON@example.test "`, `"email":"Person <person@example.test>"`, 1)} {
		request(fmt.Sprintf("bad-link-%d", i), bad, 400)
	}
	for i, foreign := range []string{strings.Replace(body, " user ", "other-user", 1), strings.Replace(body, " provider ", "other-provider", 1), strings.Replace(body, "PERSON@example.test", "other@example.test", 1)} {
		request(fmt.Sprintf("foreign-link-%d", i), foreign, 404)
	}
	if counts() != before {
		t.Fatal("denied link requests produced effects")
	}
	exec := func(query string) {
		t.Helper()
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	var recordsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records`).Scan(&recordsBefore); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		mutate, restore string
		want            int
	}{
		{`UPDATE human_users SET email='changed@example.test' WHERE id='user'`, `UPDATE human_users SET email='person@example.test' WHERE id='user'`, 404},
		{`UPDATE human_users SET tenant_id='other' WHERE id='user'`, `UPDATE human_users SET tenant_id='tenant' WHERE id='user'`, 404},
		{`UPDATE sso_providers SET tenant_id='other' WHERE id='provider'`, `UPDATE sso_providers SET tenant_id='tenant' WHERE id='provider'`, 404},
		{`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`, 403},
		{`UPDATE role_bindings SET role='collector' WHERE id='operator-grant'`, `UPDATE role_bindings SET role='tenant_admin' WHERE id='operator-grant'`, 403},
		{`UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`, `UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`, 401},
	} {
		exec(change.mutate)
		request("link", body, change.want)
		exec(change.restore)
	}
	var recordsAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records`).Scan(&recordsAfter); err != nil || recordsAfter != recordsBefore || counts() != before {
		t.Fatal("current parent/authority guard reached reservation", err)
	}
	if replay := request("link", body, 201); !reflect.DeepEqual(first, replay) {
		t.Fatal("restored authority changed replay")
	}
	emailBody := strings.Replace(body, "Subject-1", "identity@example.test", 1)
	emailFirst := request("email-subject", emailBody, 201)
	if replay := request("email-subject", emailBody, 201); !reflect.DeepEqual(emailFirst, replay) {
		t.Fatal("email-shaped subject lost on restart replay")
	}
	var saved, action, actorType, actorID, subjectType, subjectID string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='link'`).Scan(&saved); err != nil || !strings.Contains(saved, "person@example.test") || strings.Contains(saved, secret) || strings.Contains(saved, "unrelated") {
		t.Fatal("link replay metadata/privacy contract changed", err)
	}
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_type,actor_id,subject_type,subject_id FROM audit_chain_entries ORDER BY sequence LIMIT 1`).Scan(&action, &actorType, &actorID, &subjectType, &subjectID); err != nil || action != "identity_link.created" || actorType != "human_user" || actorID != "operator" || subjectType != "human_user" || subjectID != "user" {
		t.Fatal("identity link audit attribution incorrect", err)
	}
}

func TestPostgresSSOIdentityLinkWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Identity');INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('user','tenant','person@example.test','User','active','human-user.v1',now());INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Provider','oidc','https://issuer.example.test','client','active','sso-provider.v1',now())`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildSSOIdentityLinkCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	in := identityapp.LinkSSOIdentityInput{UserID: "user", ProviderID: "provider", Email: "person@example.test", Verified: true}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeLinkSSOIdentity(ctx, a, in) }}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.LinkSSOIdentity(ctx, a, in)
		return 201, domain.UserIdentityLink(v), err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM user_identity_links),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"user_identity_links", "audit_chain_entries", "replay", "commit"} {
		in.Subject = stage
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_link_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private link storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_link_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_link_stage()`
			teardown = `DROP TRIGGER reject_link_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_link_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private link storage';END$$;CREATE CONSTRAINT TRIGGER reject_link_stage AFTER INSERT ON user_identity_links DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_link_stage()`
			teardown = `DROP TRIGGER reject_link_stage ON user_identity_links`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_link_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private link storage';END$$;CREATE TRIGGER reject_link_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_link_stage()`
			teardown = `DROP TRIGGER reject_link_stage ON ` + stage
		}
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/identity-links", stage, []byte(`{}`), run); err == nil || counts() != before {
			t.Fatal("failed link left durable effects", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed link retained success receipt", err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", "/v1/sso/identity-links", stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 201 || response == nil {
				t.Fatal("rolled back link reservation cannot retry", stage, err)
			}
			for i := range before {
				before[i]++
			}
			if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/identity-links", stage, []byte(`{}`), run); err != nil {
				t.Fatal("successful link retry cannot replay", err)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed link reservation unexpectedly retried", stage, err)
		}
		if counts() != before {
			t.Fatal("link retry duplicated effects", stage)
		}
	}
	// Parent rows remain stable between authorization and actual commit. Use
	// PostgreSQL lock_timeout, not sleeps or an assumed goroutine schedule.
	in.Subject = "locked-parents"
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/sso/identity-links", "locked-parents", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		for _, query := range []string{`UPDATE human_users SET email='changed@example.test' WHERE id='user'`, `UPDATE sso_providers SET tenant_id='other' WHERE id='provider'`} {
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
				t.Fatal("identity link parent escaped transaction lock", err)
			}
		}
		return run(ctx, repos)
	}); err != nil {
		t.Fatal(err)
	}
}
