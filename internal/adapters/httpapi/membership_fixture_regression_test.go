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
	f.organization, err = ledger.CreateOrganization(t.Context(), f.actor, app.CreateOrganizationInput{Name: name, Slug: strings.ToLower(name)})
	if err != nil {
		t.Fatal(err)
	}
	f.user, err = ledger.CreateUser(t.Context(), f.actor, app.CreateUserInput{OrganizationID: f.organization.ID, Email: strings.ToLower(name) + "@example.test", DisplayName: name})
	if err != nil {
		t.Fatal(err)
	}
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
			commands := &failingMembershipFixture{membershipFixtureCommands: membershipFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
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
			operator, err := ledger.CreateUser(t.Context(), owner.actor, app.CreateUserInput{OrganizationID: owner.organization.ID, Email: "operator@example.test", DisplayName: "Operator"})
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
	commands := membershipFixtureCommands{catalogFixtureCommands{ledger: ledger}}
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
