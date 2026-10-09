package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type membershipFixtureScope struct {
	actor        domain.Actor
	organization domain.Organization
	user         domain.HumanUser
	product      domain.Product
}

func TestMembershipFixturesUseRepositoryOnlyParentsAndUsers(t *testing.T) {
	for _, action := range []string{"user", "deactivate", "role"} {
		t.Run(action, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner := seedMembershipFixtureScope(t, ledger, "Owner")
			organization, user := owner.organization, owner.user
			organization.ID, organization.Slug = "repository-org", "repository-org"
			user.ID, user.OrganizationID, user.Email = "repository-user", organization.ID, "repository@example.test"
			if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
				if err := r.Identity.InsertOrganization(ctx, organization); err != nil {
					return err
				}
				return r.Identity.InsertHumanUser(ctx, user)
			}); err != nil {
				t.Fatal(err)
			}
			commands := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			var id string
			var expectedUser domain.HumanUser
			var expectedRole domain.RoleBinding
			switch action {
			case "user":
				in := identityapp.CreateUserInput{OrganizationID: organization.ID, Email: "new-repository@example.test", DisplayName: "Repository User"}
				if err := commands.AuthorizeCreateUser(t.Context(), owner.actor, in); err != nil {
					t.Fatal(err)
				}
				v, err := commands.CreateUser(t.Context(), owner.actor, in)
				if err != nil || v.OrganizationID != organization.ID || v.Email != in.Email || v.Status != "active" {
					t.Fatal("user creation ignored repository-only parent", v, err)
				}
				id = v.ID
				expectedUser = domain.HumanUser(v)
			case "deactivate":
				if err := commands.AuthorizeDeactivateUser(t.Context(), owner.actor, user.ID); err != nil {
					t.Fatal(err)
				}
				v, err := commands.DeactivateUser(t.Context(), owner.actor, user.ID)
				if err != nil || v.ID != user.ID || v.Status != "deactivated" || v.DeactivatedAt == nil {
					t.Fatal("deactivation ignored repository-only user", v, err)
				}
				id = v.ID
				expectedUser = domain.HumanUser(v)
			case "role":
				in := identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "release_manager", ResourceType: "product", ResourceID: owner.product.ID}
				if err := commands.AuthorizeCreateRoleBinding(t.Context(), owner.actor, in); err != nil {
					t.Fatal(err)
				}
				v, err := commands.CreateRoleBinding(t.Context(), owner.actor, in)
				if err != nil || v.SubjectID != user.ID || v.ResourceID != owner.product.ID || v.Role != in.Role {
					t.Fatal("role assignment ignored repository-only user", v, err)
				}
				id = v.ID
				expectedRole = domain.RoleBinding(v)
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || id == "" {
				t.Fatal("native membership command lost metadata or audit", err)
			}
			entries := after.AuditEntries[owner.actor.TenantID]
			audit := entries[len(entries)-1]
			if audit.ActorType != "api_key" || audit.ActorID != owner.actor.KeyID || audit.SubjectID != id {
				t.Fatal("membership audit lost principal or result identity", audit)
			}
			if action == "role" {
				if after.RoleBindings[id] != expectedRole {
					t.Fatal("role result differs from persisted DTO")
				}
				delete(after.RoleBindings, id)
			} else {
				if !reflect.DeepEqual(after.Users[id], expectedUser) {
					t.Fatal("user result differs from persisted DTO")
				}
				if action == "user" {
					delete(after.Users, id)
				} else {
					after.Users[id] = before.Users[id]
				}
			}
			after.AuditEntries = before.AuditEntries
			if !reflect.DeepEqual(before, after) {
				t.Fatal("membership command changed unrelated repository state")
			}
		})
	}
}

func seedMembershipFixtureScope(t *testing.T, ledger *app.Ledger, name string) membershipFixtureScope {
	t.Helper()
	var f membershipFixtureScope
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	f.actor, err = ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	commands := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
	organization, err := commands.CreateOrganization(t.Context(), f.actor, identityapp.CreateOrganizationInput{Name: name, Slug: strings.ToLower(name)})
	if err != nil {
		t.Fatal(err)
	}
	f.organization = domain.Organization(organization)
	user, err := commands.CreateUser(t.Context(), f.actor, identityapp.CreateUserInput{OrganizationID: f.organization.ID, Email: strings.ToLower(name) + "@example.test", DisplayName: name})
	if err != nil {
		t.Fatal(err)
	}
	f.user = domain.HumanUser(user)
	f.product, err = ledger.CreateProduct(t.Context(), f.actor, name, strings.ToLower(name))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func membershipFixtureRequests(f membershipFixtureScope) []struct {
	name, path, body string
	status           int
} {
	return []struct {
		name, path, body string
		status           int
	}{
		{"organization", "/v1/organizations", `{"name":" New organization ","slug":" new-org "}`, 201},
		{"user", "/v1/users", fmt.Sprintf(`{"organization_id":%q,"email":" NEW@example.test ","display_name":" New user "}`, f.organization.ID), 201},
		{"deactivate", "/v1/users/" + f.user.ID + "/deactivate", `{}`, 200},
		{"role", "/v1/role-bindings", fmt.Sprintf(`{"subject_type":"user","subject_id":%q,"role":"release_manager","resource_type":"product","resource_id":%q}`, f.user.ID, f.product.ID), 201},
	}
}

type failingMembershipFixture struct {
	membershipFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingMembershipFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private membership failure after write")
}
func (f *failingMembershipFixture) CreateOrganization(ctx context.Context, a domain.Actor, in identityapp.CreateOrganizationInput) (identitydomain.Organization, error) {
	v, err := f.membershipFixtureCommands.CreateOrganization(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingMembershipFixture) CreateUser(ctx context.Context, a domain.Actor, in identityapp.CreateUserInput) (identitydomain.HumanUser, error) {
	v, err := f.membershipFixtureCommands.CreateUser(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingMembershipFixture) DeactivateUser(ctx context.Context, a domain.Actor, id string) (identitydomain.HumanUser, error) {
	v, err := f.membershipFixtureCommands.DeactivateUser(ctx, a, id)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingMembershipFixture) CreateRoleBinding(ctx context.Context, a domain.Actor, in identityapp.CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	v, err := f.membershipFixtureCommands.CreateRoleBinding(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}

func TestMembershipFixturesRollBackEveryEffectAfterRealWriteFailure(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedMembershipFixtureScope(t, ledger, "Owner")
		request := membershipFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingMembershipFixture{membershipFixtureCommands: membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}}
			server.membershipCommands, server.roleBindingCommands = commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, "rollback-membership", []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, "private membership") || strings.Contains(out, `"data"`) || strings.Contains(out, "new@example.test") {
				t.Fatal("failed membership command bypassed isolation or exposed partial DTO", out)
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed membership command lost its failure receipt")
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Status != 0 || r.Response != nil {
					t.Fatal("failed membership receipt retained partial response")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed membership write committed organization, user lifecycle, role, audit or job effects")
			}
		})
	}
}

func TestMembershipFixturesReplayFullDTOsOnlyWithCurrentTenantWideAuthority(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedMembershipFixtureScope(t, ledger, "Owner")
		foreign := seedMembershipFixtureScope(t, ledger, "Foreign")
		request := membershipFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			commands := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
			operator, err := commands.CreateUser(t.Context(), owner.actor, identityapp.CreateUserInput{OrganizationID: owner.organization.ID, Email: "operator@example.test", DisplayName: "Operator"})
			if err != nil {
				t.Fatal(err)
			}
			human := owner.actor
			human.KeyID, human.UserID = "", operator.ID
			human.Scopes = []string{"identity:admin"}
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"identity:admin"}}}
			auth := &configuredAuthenticator{actor: human}
			server.authn = auth
			first := postRaw(t, server, "fixture-auth", request.path, "same-membership", []byte(request.body), request.status)
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			id := dataField(t, first, "id")
			var expected any
			switch request.name {
			case "organization":
				expected = saved.Organizations[id]
			case "user", "deactivate":
				expected = saved.Users[id]
			case "role":
				expected = saved.RoleBindings[id]
			}
			want, err := json.Marshal(map[string]any{"data": expected, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first)
			last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
			if last.ActorType != "human_user" || last.ActorID != human.UserID {
				t.Fatal("membership audit lost human actor", last.ActorType, last.ActorID)
			}
			replay := postRaw(t, server, "fixture-auth", request.path, "same-membership", []byte(request.body), request.status)
			assertTrustHTTPReplay(t, first, replay)
			postRaw(t, server, "fixture-auth", request.path, "same-membership", append([]byte(request.body), ' '), 409)
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"identity:admin"}}}, {{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"identity:admin"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, "same-membership", []byte(request.body), 403)
				postRaw(t, server, "fixture-auth", request.path, "revoked-membership", []byte(request.body), 403)
			}
			auth.actor = human
			foreignBody, foreignPath := strings.NewReplacer(owner.organization.ID, foreign.organization.ID, owner.user.ID, foreign.user.ID, owner.product.ID, foreign.product.ID).Replace(request.body), strings.ReplaceAll(request.path, owner.user.ID, foreign.user.ID)
			if request.name != "organization" {
				postRaw(t, server, "fixture-auth", foreignPath, "foreign-membership", []byte(foreignBody), 404)
			}
			if request.name == "role" {
				for label, body := range map[string]string{
					"subject":  strings.ReplaceAll(request.body, owner.user.ID, foreign.user.ID),
					"resource": strings.ReplaceAll(request.body, owner.product.ID, foreign.product.ID),
				} {
					postRaw(t, server, "fixture-auth", request.path, "foreign-role-"+label, []byte(body), 404)
				}
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) {
				t.Fatal("replay/conflict/revocation/foreign guards changed stored state", err)
			}
		})
	}
}

func TestMembershipFixtureGuardsArePureAndKeepExplicitBindings(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	f := seedMembershipFixtureScope(t, ledger, "Owner")
	commands := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error {
			return commands.AuthorizeCreateOrganization(ctx, f.actor, identityapp.CreateOrganizationInput{Name: "Owner", Slug: f.organization.Slug})
		},
		func(ctx context.Context) error {
			return commands.AuthorizeCreateUser(ctx, f.actor, identityapp.CreateUserInput{OrganizationID: f.organization.ID, Email: f.user.Email, DisplayName: f.user.DisplayName})
		},
		func(ctx context.Context) error { return commands.AuthorizeDeactivateUser(ctx, f.actor, f.user.ID) },
		func(ctx context.Context) error {
			return commands.AuthorizeCreateRoleBinding(ctx, f.actor, identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: f.user.ID, Role: "release_manager", ResourceType: "product", ResourceID: f.product.ID})
		},
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("real focused guard rejected owned preexisting subject", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("membership guard ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("membership preflight changed authoritative state", err)
	}
	membership, role := &membershipHTTPFake{}, &roleBindingHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{MembershipCommands: membership, RoleBindingCommands: role, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	server.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if server.membershipCommands != membership || server.roleBindingCommands != role {
		t.Fatal("fixture binding replaced explicit focused commands")
	}
}

func TestMembershipNativeFixturesPreserveClockDuringRebinding(t *testing.T) {
	ledger, _ := integrationRegressionLedger()
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	member := s.membershipCommands.(membershipFixtureCommands)
	member.clock = clock
	s.membershipCommands = member
	role := s.roleBindingCommands.(membershipFixtureCommands)
	role.clock = clock
	s.roleBindingCommands = role
	second := newLegacyLedgerFixture(app.Config{UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	s.bindLegacyLedgerFixture(second)
	for name, port := range map[string]any{"member": s.membershipCommands, "role": s.roleBindingCommands} {
		f := port.(membershipFixtureCommands)
		if f.ledger != second || f.clock != clock {
			t.Fatal("membership fixture rebinding lost explicit clock or transaction owner", name)
		}
	}
}
