package httpapi

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These scoped readers serve existing local HTTP fixtures only. Production
// metadata queries enforce tenant/limit predicates in PostgreSQL.
type apiKeyFixtureQuery struct{ catalogFixtureCommands }

func (f apiKeyFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.APIKey], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	values, err := f.commandLedger(ctx).ListAPIKeys(ctx, actor)
	if err != nil {
		return appquery.Result[identitydomain.APIKey]{}, err
	}
	items := make([]identitydomain.APIKey, 0, len(values))
	for _, value := range values {
		key := identitydomain.APIKey(value)
		key.Hash = ""
		items = append(items, key)
	}
	return appquery.Page(items, request, after, func(value identitydomain.APIKey, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}

type roleBindingFixtureQuery struct{ catalogFixtureCommands }

func (f roleBindingFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[identitydomain.RoleBinding], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	values, err := f.commandLedger(ctx).ListRoleBindings(ctx, actor)
	if err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, err
	}
	items := make([]identitydomain.RoleBinding, 0, len(values))
	for _, value := range values {
		items = append(items, identitydomain.RoleBinding(value))
	}
	return appquery.Page(items, request, after, func(value identitydomain.RoleBinding, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
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
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper"})
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
		org, err := ledger.CreateOrganization(t.Context(), actor, app.CreateOrganizationInput{Name: name, Slug: name})
		if err != nil {
			t.Fatal(err)
		}
		user, err := ledger.CreateUser(t.Context(), actor, app.CreateUserInput{OrganizationID: org.ID, Email: name + "@example.test", DisplayName: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.CreateRoleBinding(t.Context(), actor, app.CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "tenant_admin", ResourceType: "tenant", ResourceID: actor.TenantID}); err != nil {
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
