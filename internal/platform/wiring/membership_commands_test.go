package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresMembershipHTTPOwnsWritesReplayAndDeactivation(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Membership'),('other','Other'),('foreign','Foreign')`); err != nil {
		t.Fatal(err)
	}
	if c, err := BuildMembershipCommands(nil); err == nil || c != nil {
		t.Fatal("missing membership transaction accepted")
	}
	auth := &attestationHTTPActor{actor: domain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}}
	request := func(path, key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "membership-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.MembershipCommands == nil {
			t.Fatal("membership still uses Ledger", err)
		}
		opts.Authenticator = auth
		noReload := newAggregateLoadCanary(t, ctx, store)
		s, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(ctx) || strings.Contains(w.Body.String(), "private membership storage") {
			t.Fatal("membership status or bounded persistence changed", w.Code, noReload.Intact(ctx))
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("membership error lacks Problem Details")
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
	counts := func() [4]int {
		t.Helper()
		var v [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM organizations),(SELECT count(*)FROM human_users),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	orgBody := `{"name":"Example","slug":"CasePreserved"}`
	org := request("/v1/organizations", "org", orgBody, 201)
	if org["slug"] != "CasePreserved" || org["schema_version"] != domain.OrganizationSchemaVersion {
		t.Fatal("organization DTO incompatible")
	}
	if replay := request("/v1/organizations", "org", orgBody, 201); !reflect.DeepEqual(org, replay) || counts() != [4]int{1, 0, 1, 1} {
		t.Fatal("restart organization replay changed")
	}
	request("/v1/organizations", "org", `{"name":"Changed","slug":"CasePreserved"}`, 409)
	request("/v1/organizations", "duplicate-org", orgBody, 409)
	userBody := `{"organization_id":"` + org["id"].(string) + `","email":" PERSON@EXAMPLE.TEST ","display_name":" Person "}`
	user := request("/v1/users", "user", userBody, 201)
	if user["email"] != "person@example.test" || user["display_name"] != "Person" || user["schema_version"] != domain.HumanUserSchemaVersion || user["status"] != "active" {
		t.Fatal("public user DTO lost")
	}
	if replay := request("/v1/users", "user", userBody, 201); !reflect.DeepEqual(user, replay) || counts() != [4]int{1, 1, 2, 2} {
		t.Fatal("restart user replay lost required email or duplicated effects")
	}
	request("/v1/users", "duplicate-user", userBody, 409)
	request("/v1/users", "bad-email", `{"email":"bad@@example.test","display_name":"Person"}`, 400)
	request("/v1/users", "missing-user-fields", `{}`, 400)
	request("/v1/organizations", "missing-org-fields", `{}`, 400)
	// Identical actor/key names cannot cross tenant replay or uniqueness scope.
	auth.actor.TenantID = "other"
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"admin"}}}
	otherOrg := request("/v1/organizations", "org", orgBody, 201)
	otherBody := strings.Replace(userBody, org["id"].(string), otherOrg["id"].(string), 1)
	otherUser := request("/v1/users", "user", otherBody, 201)
	if otherOrg["id"] == org["id"] || otherUser["id"] == user["id"] || otherUser["tenant_id"] != "other" {
		t.Fatal("tenant replay or natural identity isolation lost")
	}
	if replay := request("/v1/users", "user", otherBody, 201); !reflect.DeepEqual(replay, otherUser) {
		t.Fatal("second tenant user replay lost")
	}
	auth.actor.TenantID = "tenant"
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}
	before := counts()
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"admin"}}}, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"admin"}}}} {
		auth.actor.ResourceGrants = grants
		request("/v1/users", "user", userBody, 403)
		request("/v1/organizations", "org", orgBody, 403)
	}
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}
	if _, err := pool.Exec(ctx, `UPDATE organizations SET tenant_id='foreign',name=repeat('x',9437184) WHERE id=$1`, org["id"]); err != nil {
		t.Fatal(err)
	}
	request("/v1/users", "user", userBody, 404)
	request("/v1/users/"+user["id"].(string)+"/deactivate", "foreign-parent", `{}`, 404)
	if counts() != before {
		t.Fatal("denied replay changed membership")
	}
	if _, err := pool.Exec(ctx, `UPDATE organizations SET tenant_id='tenant' WHERE id=$1`, org["id"]); err != nil {
		t.Fatal(err)
	}
	// Large parent metadata is never selected for the membership reference.
	request("/v1/users", "bounded-parent", strings.Replace(userBody, "PERSON@EXAMPLE.TEST", "SECOND@EXAMPLE.TEST", 1), 201)
	path := "/v1/users/" + user["id"].(string) + "/deactivate"
	if _, err := pool.Exec(ctx, `UPDATE human_users SET tenant_id='foreign' WHERE id=$1`, user["id"]); err != nil {
		t.Fatal(err)
	}
	request(path, "foreign-user", `{}`, 404)
	if _, err := pool.Exec(ctx, `UPDATE human_users SET tenant_id='tenant',display_name=repeat('x',9437184) WHERE id=$1`, user["id"]); err != nil {
		t.Fatal(err)
	}
	request(path, "oversized-user", `{}`, 409)
	if _, err := pool.Exec(ctx, `UPDATE human_users SET display_name='Person' WHERE id=$1`, user["id"]); err != nil {
		t.Fatal(err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("membership-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const sessionSecret = "evysso_membership_fixture"
	if _, err := pool.Exec(ctx, `INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('provider','tenant','Fixture','oidc','https://issuer.example.test','client','active','sso-provider.v1',now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_bindings(id,tenant_id,subject_type,subject_id,role,resource_type,resource_id,schema_version,created_at)VALUES('role','tenant','user',$1,'tenant_admin','tenant','tenant','role-binding.v1',now())`, user["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('session','tenant',$1,'provider',$2,$3,now()+interval '1 hour','sso-session.v1',now())`, user["id"], credentials.Prefix(sessionSecret), credentials.Hash(sessionSecret)); err != nil {
		t.Fatal(err)
	}
	authn, err := BuildAuthenticator(store, store, "membership-test-pepper", true)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := authn.Authenticate(ctx, sessionSecret); err != nil || a.UserID != user["id"] {
		t.Fatal("fixture session invalid", err)
	}
	before = counts()
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_membership_audit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private membership storage';END$$;CREATE TRIGGER reject_membership_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_membership_audit()`); err != nil {
		t.Fatal(err)
	}
	request(path, "audit-failure", `{}`, 500)
	if counts() != before {
		t.Fatal("failed deactivation committed effects")
	}
	if _, err := authn.Authenticate(ctx, sessionSecret); err != nil {
		t.Fatal("failed deactivation revoked a valid session", err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_membership_audit ON audit_chain_entries`); err != nil {
		t.Fatal(err)
	}
	request(path, "audit-failure", `{}`, 409)
	deactivated := request(path, "deactivate", `{}`, 200)
	if deactivated["status"] != "deactivated" || deactivated["email"] != "person@example.test" || deactivated["deactivated_at"] == nil {
		t.Fatal("deactivation contract lost")
	}
	before = counts()
	if replay := request(path, "deactivate", `{}`, 200); !reflect.DeepEqual(deactivated, replay) || counts() != before {
		t.Fatal("completed deactivation cannot replay")
	}
	request(path, "deactivate-again", `{}`, 409)
	if _, err := authn.Authenticate(ctx, sessionSecret); !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatal("deactivated user session still authenticates", err)
	}
	var saved string
	if err := pool.QueryRow(ctx, `SELECT response::text FROM idempotency_records WHERE idempotency_key='deactivate'`).Scan(&saved); err != nil || !strings.Contains(saved, "person@example.test") || strings.Contains(saved, sessionSecret) || strings.Contains(saved, credentials.Hash(sessionSecret)) {
		t.Fatal("replay data contract or privacy changed", err)
	}
	var action, actorID, actorType string
	if err := pool.QueryRow(ctx, `SELECT entry_type,actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1 ORDER BY sequence DESC LIMIT 1`, user["id"]).Scan(&action, &actorID, &actorType); err != nil || action != "user.deactivated" || actorID != "operator" || actorType != "human_user" {
		t.Fatal("membership audit attribution lost", err)
	}
}

func TestPostgresMembershipConcurrentNormalizedIdentityHasOneWinner(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Membership')`); err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	for _, operation := range []string{"organization", "user"} {
		results := make(chan error, 6)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			c, err := BuildMembershipCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				var err error
				if operation == "organization" {
					_, err = c.CreateOrganization(t.Context(), a, identityapp.CreateOrganizationInput{Name: "Example", Slug: " shared "})
				} else {
					_, err = c.CreateUser(t.Context(), a, identityapp.CreateUserInput{Email: " PERSON@EXAMPLE.TEST ", DisplayName: "Person"})
				}
				results <- err
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		wins, conflicts := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, identityapp.ErrConflict) {
				conflicts++
			} else {
				t.Fatal("unexpected membership concurrency failure", err)
			}
		}
		if wins != 1 || conflicts != 5 {
			t.Fatal("duplicate identity race", wins, conflicts)
		}
	}
	var orgs, users, audits int
	if err := pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM organizations),(SELECT count(*)FROM human_users),(SELECT count(*)FROM audit_chain_entries)`).Scan(&orgs, &users, &audits); err != nil || orgs != 1 || users != 1 || audits != 2 {
		t.Fatal("duplicate identity race leaked effects", err)
	}
}

func TestPostgresMembershipEveryWriteAuditReplayAndCommitFailureRollsBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Membership')`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildMembershipCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"identity:admin"}}
	counts := func() [4]int {
		t.Helper()
		var v [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM organizations),(SELECT count(*)FROM human_users),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, op := range []string{"organization", "user", "deactivate"} {
		for _, stage := range []string{"write", "audit", "replay", "commit"} {
			name := op + "-" + stage
			var target string
			if op == "deactivate" {
				u, err := c.CreateUser(ctx, a, identityapp.CreateUserInput{Email: name + "@example.test", DisplayName: "Person"})
				if err != nil {
					t.Fatal(err)
				}
				target = u.ID
			}
			inOrg := identityapp.CreateOrganizationInput{Name: "Example", Slug: name}
			inUser := identityapp.CreateUserInput{Email: name + "@example.test", DisplayName: "Person"}
			guard := func(ctx context.Context, _ app.Repositories) error {
				switch op {
				case "organization":
					return c.AuthorizeCreateOrganization(ctx, a, inOrg)
				case "user":
					return c.AuthorizeCreateUser(ctx, a, inUser)
				default:
					return c.AuthorizeDeactivateUser(ctx, a, target)
				}
			}
			run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
				switch op {
				case "organization":
					v, err := c.CreateOrganization(ctx, a, inOrg)
					return 201, domain.Organization(v), err
				case "user":
					v, err := c.CreateUser(ctx, a, inUser)
					return 201, domain.HumanUser(v), err
				default:
					v, err := c.DeactivateUser(ctx, a, target)
					return 200, domain.HumanUser(v), err
				}
			}
			executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: guard}
			table, event := "human_users", "INSERT"
			if op == "organization" {
				table = "organizations"
			}
			if op == "deactivate" {
				event = "UPDATE"
			}
			var setup, teardown string
			switch stage {
			case "replay":
				setup = `CREATE OR REPLACE FUNCTION reject_membership_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.state='completed' THEN RAISE EXCEPTION 'private membership storage';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_membership_stage BEFORE UPDATE ON idempotency_records FOR EACH ROW EXECUTE FUNCTION reject_membership_stage()`
				teardown = `DROP TRIGGER reject_membership_stage ON idempotency_records`
			case "commit":
				setup = fmt.Sprintf(`CREATE OR REPLACE FUNCTION reject_membership_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private membership storage';END$$;CREATE CONSTRAINT TRIGGER reject_membership_stage AFTER %s ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_membership_stage()`, event, table)
				teardown = `DROP TRIGGER reject_membership_stage ON ` + table
			default:
				if stage == "audit" {
					table, event = "audit_chain_entries", "INSERT"
				}
				setup = fmt.Sprintf(`CREATE OR REPLACE FUNCTION reject_membership_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private membership storage';END$$;CREATE TRIGGER reject_membership_stage BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_membership_stage()`, event, table)
				teardown = `DROP TRIGGER reject_membership_stage ON ` + table
			}
			before := counts()
			if _, err := pool.Exec(ctx, setup); err != nil {
				t.Fatal(err)
			}
			_, _, err = executor.WithBody(ctx, a, "POST", "/membership/"+op, name, []byte(`{}`), run)
			if err == nil || counts() != before {
				t.Fatal("membership fault left partial effects", name, err)
			}
			if target != "" {
				var status string
				if err := pool.QueryRow(ctx, `SELECT status FROM human_users WHERE id=$1`, target).Scan(&status); err != nil || status != "active" {
					t.Fatal("failed deactivation mutated user", name, err)
				}
			}
			var unsafe int
			if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE idempotency_key=$1 AND(response<>'null'::jsonb OR status<>0)`, name).Scan(&unsafe); err != nil || unsafe != 0 {
				t.Fatal("failed membership retained success response", name, err)
			}
			if _, err := pool.Exec(ctx, teardown); err != nil {
				t.Fatal(err)
			}
			status, response, err := executor.WithBody(ctx, a, "POST", "/membership/"+op, name, []byte(`{}`), run)
			if stage == "replay" || stage == "commit" {
				want := 201
				if op == "deactivate" {
					want = 200
				}
				if err != nil || status != want || response == nil {
					t.Fatal("rolled-back reservation cannot retry", name, err)
				}
				switch op {
				case "organization":
					before[0]++
				case "user":
					before[1]++
				}
				before[2]++
				before[3]++
				if _, _, err := executor.WithBody(ctx, a, "POST", "/membership/"+op, name, []byte(`{}`), run); err != nil {
					t.Fatal("completed fault retry cannot replay", name, err)
				}
			} else if !errors.Is(err, app.ErrIdempotencyFailed) {
				t.Fatal("failed reservation unexpectedly retried", name, err)
			}
			if counts() != before {
				t.Fatal("membership failure retry repeated effects", name)
			}
		}
	}
}
