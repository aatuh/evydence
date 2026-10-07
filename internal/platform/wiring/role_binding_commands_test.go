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

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresRoleBindingHTTPChecksCurrentAuthorityParentsAndPrivateReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if c, err := BuildRoleBindingCommands(nil); err == nil || c != nil {
		t.Fatal("missing role transactions accepted")
	}
	setup := `
INSERT INTO tenants(id,name)VALUES('tenant','Roles'),('other','Other'),('foreign','Foreign');
INSERT INTO products(id,tenant_id,name,slug,created_at)VALUES('product','tenant','Product','product',now()),('alternate','tenant','Alternate','alternate',now()),('other-product','other','Other','other',now());
INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9437184));
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft');
INSERT INTO organizations(id,tenant_id,name,slug,status,schema_version,created_at)VALUES('org','tenant','Example','example','active','organization.v1',now());
INSERT INTO human_users(id,tenant_id,organization_id,email,display_name,status,schema_version,created_at)VALUES('user','tenant','org','user@example.test',repeat('x',9437184),'active','human-user.v1',now()),('operator','tenant',NULL,'operator@example.test','Operator','active','human-user.v1',now()),('other-user','other',NULL,'other@example.test','Other','active','human-user.v1',now());
INSERT INTO api_keys(id,tenant_id,name,prefix,hash,scopes,created_at)VALUES('collector-key','tenant',repeat('x',9437184),'fixture-prefix','private-credential-hash','[]',now());
INSERT INTO collectors(id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version,created_at)VALUES('collector','tenant','Collector','custom',repeat('x',9437184),'collector-key','active','[]','collector.v1',now());
INSERT INTO redaction_profiles(id,tenant_id,name,schema_version,created_at)VALUES('profile','tenant','Public','redaction-profile.v1',now());
INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('package','tenant','product','release','profile',repeat('x',9437184),'published',jsonb_build_object('unrelated',repeat('x',9437184)),'hash',now()+interval '1 day','customer-security-package.v1',now());
INSERT INTO evidence_bundles(id,tenant_id,release_id,evidence_ids,manifest,manifest_hash,verification_text,schema_version,created_at)VALUES('bundle','tenant','release','{}',jsonb_build_object('unrelated',repeat('x',9437184)),'hash','Verify locally','evidence-bundle.v1',now());
INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Fixture','oidc','https://issuer.example.test','client','active','sso-provider.v1',now());
INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('operator-grant','tenant','user','operator','tenant_admin','tenant','tenant','role-binding.v1',now());`
	if _, err := pool.Exec(ctx, setup); err != nil {
		t.Fatal(err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("role-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evysso_role_fixture"
	const targetSecret = "evysso_target_role_fixture"
	for _, session := range []struct{ id, user, secret string }{{"operator-session", "operator", secret}, {"target-session", "user", targetSecret}} {
		if _, err := pool.Exec(ctx, `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES($1,'tenant',$2,'provider',$3,$4,now()+interval '1 hour','sso-session.v1',now())`, session.id, session.user, credentials.Prefix(session.secret), credentials.Hash(session.secret)); err != nil {
			t.Fatal(err)
		}
	}
	authn, err := BuildAuthenticator(store, store, "role-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := authn.Authenticate(ctx, targetSecret); !errors.Is(err, identityapp.ErrForbidden) || a.HasScope("identity:admin") {
		t.Fatal("unassigned user already has role authority", err)
	}
	request := func(key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "role-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.RoleBindingCommands == nil {
			t.Fatal("role assignment remains Ledger-backed", err)
		}
		noReload := newAggregateLoadCanary(t, ctx, store)
		s, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/role-bindings", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(ctx) || strings.Contains(w.Body.String(), "private role storage") || strings.Contains(w.Body.String(), "private-credential-hash") || len(w.Body.Bytes()) > 32768 {
			t.Fatal("role response or bounded persistence changed", w.Code, noReload.Intact(ctx))
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("role error lacks Problem Details")
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
	body := func(subject, kind, id, role string) string {
		t.Helper()
		raw, err := json.Marshal(map[string]string{"subject_type": subject, "subject_id": subject, "role": role, "resource_type": kind, "resource_id": id})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM role_bindings),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	resources := []struct{ kind, id string }{{"", ""}, {"tenant", ""}, {"tenant", "tenant"}, {"product", "product"}, {"project", "project"}, {"release", "release"}, {"customer_security_package", "package"}, {"evidence_bundle", "bundle"}}
	for _, subject := range []string{"user", "collector"} {
		for i, resource := range resources {
			key := fmt.Sprintf("role-%s-%d", subject, i)
			in := body(subject, resource.kind, resource.id, "release_manager")
			first := request(key, in, 201)
			before := counts()
			if first["subject_type"] != subject || first["subject_id"] != subject || first["tenant_id"] != "tenant" || first["schema_version"] != domain.RoleBindingSchemaVersion {
				t.Fatal("role DTO contract lost")
			}
			if replay := request(key, in, 201); !reflect.DeepEqual(first, replay) || counts() != before {
				t.Fatal("restart role replay duplicated effects")
			}
		}
	}
	// A new key is a new assignment; identical semantic grants are not deduplicated.
	adminBody := body("user", "tenant", "tenant", "tenant_admin")
	first := request("target-admin", adminBody, 201)
	again := request("target-admin-again", adminBody, 201)
	if first["id"] == again["id"] {
		t.Fatal("repeated assignment was silently reused")
	}
	if a, err := authn.Authenticate(ctx, targetSecret); err != nil || !a.HasScope("identity:admin") || a.HasExplicitScope("instance:admin") {
		t.Fatal("current role assignment failed or granted instance authority", err)
	}
	request("target-admin", body("user", "tenant", "tenant", "collector"), 409)
	before := counts()
	for _, in := range []string{`{}`, `{"subject_type":"user","subject_id":"user","role":"instance:admin"}`, `{"subject_type":"user","subject_id":"user","role":"collector","resource_type":"tenant","resource_id":null}`} {
		request("bad-role", in, 400)
	}
	for _, kind := range []string{"product", "project", "release", "customer_security_package", "evidence_bundle"} {
		request("empty-"+kind, body("user", kind, "", "release_manager"), 404)
	}
	request("foreign-tenant", body("user", "tenant", "other", "tenant_admin"), 404)
	request("foreign-subject", strings.Replace(adminBody, `"subject_id":"user"`, `"subject_id":"other-user"`, 1), 404)
	if counts() != before {
		t.Fatal("denied role requests produced effects")
	}
	exec := func(query string) {
		t.Helper()
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	// Current subject parents are checked even when a completed replay exists.
	exec(`UPDATE organizations SET tenant_id='foreign' WHERE id='org'`)
	request("target-admin", adminBody, 404)
	exec(`UPDATE organizations SET tenant_id='tenant' WHERE id='org'`)
	exec(`UPDATE human_users SET tenant_id='foreign' WHERE id='user'`)
	request("target-admin", adminBody, 404)
	exec(`UPDATE human_users SET tenant_id='tenant' WHERE id='user'`)
	exec(`UPDATE api_keys SET tenant_id='foreign' WHERE id='collector-key'`)
	request("role-collector-0", body("collector", "", "", "release_manager"), 404)
	exec(`UPDATE api_keys SET tenant_id='tenant' WHERE id='collector-key'`)
	exec(`UPDATE collectors SET tenant_id='foreign' WHERE id='collector'`)
	request("role-collector-0", body("collector", "", "", "release_manager"), 404)
	exec(`UPDATE collectors SET tenant_id='tenant' WHERE id='collector'`)
	for i, target := range []struct{ table, id, kind string }{{"products", "product", "product"}, {"projects", "project", "project"}, {"releases", "release", "release"}, {"customer_security_packages", "package", "customer_security_package"}, {"evidence_bundles", "bundle", "evidence_bundle"}} {
		// Table names are fixed fixture constants, never request input.
		exec(fmt.Sprintf("UPDATE %s SET tenant_id='foreign' WHERE id='%s'", target.table, target.id))
		request(fmt.Sprintf("role-user-%d", i+3), body("user", target.kind, target.id, "release_manager"), 404)
		exec(fmt.Sprintf("UPDATE %s SET tenant_id='tenant' WHERE id='%s'", target.table, target.id))
	}
	// Coherent current resource parents, not saved role coordinates, determine replay.
	exec(`UPDATE products SET tenant_id='foreign' WHERE id='product'`)
	for i, resource := range resources[3:7] {
		request(fmt.Sprintf("role-user-%d", i+3), body("user", resource.kind, resource.id, "release_manager"), 404)
	}
	request("role-user-7", body("user", "evidence_bundle", "bundle", "release_manager"), 404)
	exec(`UPDATE products SET tenant_id='tenant' WHERE id='product'`)
	exec(`UPDATE projects SET product_id='other-product' WHERE id='project'`)
	request("role-user-4", body("user", "project", "project", "release_manager"), 404)
	exec(`UPDATE projects SET product_id='product' WHERE id='project'`)
	exec(`UPDATE releases SET product_id='alternate' WHERE id='release'`)
	request("role-user-6", body("user", "customer_security_package", "package", "release_manager"), 404)
	exec(`UPDATE releases SET product_id='product' WHERE id='release'`)
	exec(`UPDATE releases SET tenant_id='foreign' WHERE id='release'`)
	request("role-user-7", body("user", "evidence_bundle", "bundle", "release_manager"), 404)
	exec(`UPDATE releases SET tenant_id='tenant' WHERE id='release'`)
	// Optional release links remain optional, including on completed replay.
	for _, target := range []struct{ table, id, key, kind string }{{"customer_security_packages", "package", "role-user-6", "customer_security_package"}, {"evidence_bundles", "bundle", "role-user-7", "evidence_bundle"}} {
		exec(fmt.Sprintf("UPDATE %s SET release_id=NULL WHERE id='%s'", target.table, target.id))
		request(target.key, body("user", target.kind, target.id, "release_manager"), 201)
		exec(fmt.Sprintf("UPDATE %s SET release_id='release' WHERE id='%s'", target.table, target.id))
	}
	if counts() != before {
		t.Fatal("current parent denials changed durable effects")
	}
	// Real SSO authentication re-reads current grants before saved success replay.
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='operator-grant'`)
	request("target-admin", adminBody, 403)
	exec(`UPDATE role_bindings SET tenant_id='other' WHERE id='operator-grant'`)
	request("target-admin", adminBody, 403)
	exec(`UPDATE role_bindings SET tenant_id='tenant',resource_type='tenant',resource_id='tenant' WHERE id='operator-grant'`)
	exec(`UPDATE human_users SET status='deactivated',deactivated_at=now() WHERE id='operator'`)
	request("target-admin", adminBody, 401)
	exec(`UPDATE human_users SET status='active',deactivated_at=NULL WHERE id='operator'`)
	if replay := request("target-admin", adminBody, 201); !reflect.DeepEqual(replay, first) || counts() != before {
		t.Fatal("restored authority replay changed")
	}
	var saved, action, actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='target-admin'`).Scan(&saved); err != nil || strings.Contains(saved, secret) || strings.Contains(saved, "private-credential-hash") {
		t.Fatal("role replay retained credentials", err)
	}
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, first["id"]).Scan(&action, &actorType, &actorID); err != nil || action != "role_binding.created" || actorType != "human_user" || actorID != "operator" {
		t.Fatal("role audit attribution incorrect", err)
	}
}

func TestPostgresRoleBindingWriteAuditReplayAndDeferredCommitFailuresRollBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Roles');INSERT INTO human_users(id,tenant_id,email,display_name,status,schema_version,created_at)VALUES('user','tenant','user@example.test','User','active','human-user.v1',now())`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildRoleBindingCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	in := identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: "user", Role: "security_engineer", ResourceType: "tenant"}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeCreateRoleBinding(ctx, a, in) }}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateRoleBinding(ctx, a, in)
		return 201, domain.RoleBinding(v), err
	}
	counts := func() [3]int {
		t.Helper()
		var v [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM role_bindings),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, stage := range []string{"role_bindings", "audit_chain_entries", "replay", "commit"} {
		var setup, teardown string
		switch stage {
		case "replay":
			setup = `CREATE OR REPLACE FUNCTION reject_role_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private role storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_role_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_role_stage()`
			teardown = `DROP TRIGGER reject_role_stage ON idempotency_records`
		case "commit":
			setup = `CREATE OR REPLACE FUNCTION reject_role_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private role storage';END$$;CREATE CONSTRAINT TRIGGER reject_role_stage AFTER INSERT ON role_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_role_stage()`
			teardown = `DROP TRIGGER reject_role_stage ON role_bindings`
		default:
			setup = `CREATE OR REPLACE FUNCTION reject_role_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private role storage';END$$;CREATE TRIGGER reject_role_stage BEFORE INSERT ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_role_stage()`
			teardown = `DROP TRIGGER reject_role_stage ON ` + stage
		}
		before := counts()
		if _, err := pool.Exec(ctx, setup); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/role-bindings", stage, []byte(`{}`), run); err == nil || counts() != before {
			t.Fatal("failed role assignment left effects", stage, err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, stage).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("failed role assignment retained success replay", stage, err)
		}
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Fatal(err)
		}
		status, response, err := executor.WithBody(ctx, a, "POST", "/v1/role-bindings", stage, []byte(`{}`), run)
		if stage == "replay" || stage == "commit" {
			if err != nil || status != 201 || response == nil {
				t.Fatal("rolled back role reservation cannot retry", stage, err)
			}
			for i := range before {
				before[i]++
			}
			if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/role-bindings", stage, []byte(`{}`), run); err != nil {
				t.Fatal("completed role retry cannot replay", stage, err)
			}
		} else if !errors.Is(err, app.ErrIdempotencyFailed) {
			t.Fatal("failed role reservation unexpectedly retried", stage, err)
		}
		if counts() != before {
			t.Fatal("role fault retry duplicated effects", stage)
		}
	}
}
