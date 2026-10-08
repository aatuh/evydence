package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

// These scoped readers serve existing local HTTP fixtures only. Production
// metadata queries enforce tenant/limit predicates in PostgreSQL.
type apiKeyFixtureQuery struct{ catalogFixtureCommands }

func (f apiKeyFixtureQuery) PageAPIKeys(ctx context.Context, req identityquery.APIKeyPageRequest) (appquery.Result[identitydomain.APIKey], error) {
	var out appquery.Result[identitydomain.APIKey]
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityquery.APIKeyReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageAPIKeys(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	return out, nil
}

func (f apiKeyFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.APIKey], error) {
	q, err := identityquery.NewAPIKeys(f)
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	v, err := q.ListPage(ctx, actor, request, after)
	return v, providerVerificationFixtureError(err)
}

func TestRoleBindingFixturePagesRepositoryOnlyAssignments(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedMembershipFixtureScope(t, ledger, "Owner")
	binding := domain.RoleBinding{ID: "repository-role", TenantID: owner.actor.TenantID, SubjectType: "user", SubjectID: owner.user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: owner.actor.TenantID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: owner.user.CreatedAt}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error { return r.Identity.InsertRoleBinding(ctx, binding) }); err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f := roleBindingFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	got, err := f.ListPage(t.Context(), owner.actor, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(got.Items) != 1 || got.Next != nil || got.Items[0] != identitydomain.RoleBinding(binding) {
		t.Fatal("role page ignored repository-only assignment", got, err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("role query changed repository state", err)
	}
}

type roleBindingFixtureQuery struct{ catalogFixtureCommands }

func (f roleBindingFixtureQuery) PageRoleBindings(ctx context.Context, req identityquery.RoleBindingPageRequest) (appquery.Result[identitydomain.RoleBinding], error) {
	var out appquery.Result[identitydomain.RoleBinding]
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityquery.RoleBindingReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageRoleBindings(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	return out, nil
}

func (f roleBindingFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.RoleBinding], error) {
	q, err := identityquery.NewRoleBindings(f)
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	result, err := q.ListPage(ctx, actor, request, after)
	return result, providerVerificationFixtureError(err)
}

func (s *Server) bindIdentityQueryFixturePorts(ledger *app.Ledger) {
	if _, fixture := s.apiKeyQuery.(apiKeyFixtureQuery); s.apiKeyQuery == nil || fixture {
		s.apiKeyQuery = apiKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	}
	if _, fixture := s.roleBindingQuery.(roleBindingFixtureQuery); s.roleBindingQuery == nil || fixture {
		s.roleBindingQuery = roleBindingFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	}
}

var (
	_ APIKeyQuery      = apiKeyFixtureQuery{}
	_ RoleBindingQuery = roleBindingFixtureQuery{}
)

func TestIdentityQueryFixturesPreserveTenantIsolationAndAdminChecks(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	keys := apiKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	roles := roleBindingFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	var actors []domain.Actor
	for _, name := range []string{"Alpha", "Bravo"} {
		_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := ledger.Authenticate(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		actors = append(actors, actor)
		commands := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
		org, err := commands.CreateOrganization(t.Context(), actor, identityapp.CreateOrganizationInput{Name: name, Slug: name})
		if err != nil {
			t.Fatal(err)
		}
		user, err := commands.CreateUser(t.Context(), actor, identityapp.CreateUserInput{OrganizationID: org.ID, Email: name + "@example.test", DisplayName: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := commands.CreateRoleBinding(t.Context(), actor, identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "tenant_admin", ResourceType: "tenant", ResourceID: actor.TenantID}); err != nil {
			t.Fatal(err)
		}
	}
	for _, actor := range actors {
		keyPage, err := keys.ListPage(t.Context(), actor, page, nil)
		if err != nil || len(keyPage.Items) != 1 || keyPage.Items[0].TenantID != actor.TenantID || keyPage.Items[0].ID != actor.KeyID || keyPage.Items[0].Hash != "" || keyPage.Next != nil {
			t.Fatal("fixture key page leaked another tenant or credential hash", err)
		}
		rolePage, err := roles.ListPage(t.Context(), actor, page, nil)
		if err != nil || len(rolePage.Items) != 1 || rolePage.Items[0].TenantID != actor.TenantID || rolePage.Next != nil {
			t.Fatal("fixture role page leaked another tenant", err)
		}
		actor.Scopes = []string{"evidence:read"}
		if _, err := keys.ListPage(t.Context(), actor, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture key query skipped admin authority", err)
		}
		if _, err := roles.ListPage(t.Context(), actor, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture role query skipped admin authority", err)
		}
	}
}
