package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type membershipHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	org              identityapp.CreateOrganizationInput
	user             identityapp.CreateUserInput
	id               string
	guardErr, runErr error
}

func (f *membershipHTTPFake) AuthorizeCreateOrganization(_ context.Context, a identitydomain.Actor, in identityapp.CreateOrganizationInput) error {
	f.guards++
	f.actor, f.org = a, in
	return f.guardErr
}
func (f *membershipHTTPFake) AuthorizeCreateUser(_ context.Context, a identitydomain.Actor, in identityapp.CreateUserInput) error {
	f.guards++
	f.actor, f.user = a, in
	return f.guardErr
}
func (f *membershipHTTPFake) AuthorizeDeactivateUser(_ context.Context, a identitydomain.Actor, id string) error {
	f.guards++
	f.actor, f.id = a, id
	return f.guardErr
}
func (f *membershipHTTPFake) CreateOrganization(_ context.Context, a identitydomain.Actor, in identityapp.CreateOrganizationInput) (identitydomain.Organization, error) {
	f.calls++
	return identitydomain.Organization{ID: "org", TenantID: a.TenantID, Name: in.Name, Slug: in.Slug, Status: "active", SchemaVersion: identitydomain.OrganizationSchemaVersion, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, f.runErr
}
func (f *membershipHTTPFake) CreateUser(_ context.Context, a identitydomain.Actor, in identityapp.CreateUserInput) (identitydomain.HumanUser, error) {
	f.calls++
	return identitydomain.HumanUser{ID: "user", TenantID: a.TenantID, OrganizationID: in.OrganizationID, Email: in.Email, DisplayName: in.DisplayName, Status: "active", SchemaVersion: identitydomain.HumanUserSchemaVersion, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, f.runErr
}
func (f *membershipHTTPFake) DeactivateUser(_ context.Context, a identitydomain.Actor, id string) (identitydomain.HumanUser, error) {
	f.calls++
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return identitydomain.HumanUser{ID: id, TenantID: a.TenantID, Email: "person@example.test", DisplayName: "Person", Status: "deactivated", DeactivatedAt: &now, SchemaVersion: identitydomain.HumanUserSchemaVersion, CreatedAt: now}, f.runErr
}
func TestMembershipHTTPDispatchesFocusedCommandsAndGuardsStrictJSON(t *testing.T) {
	base, secret := testServer(t)
	f := &membershipHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{MembershipCommands: f}); err == nil {
		t.Fatal("membership silently kept Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{MembershipCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []struct {
		path, body, field string
		status            int
	}{
		{"/v1/organizations", `{"name":"Example","slug":"example"}`, `"slug":"example"`, 201},
		{"/v1/users", `{"organization_id":"org","email":"person@example.test","display_name":"Person"}`, `"email":"person@example.test"`, 201},
		{"/v1/users/user/deactivate", `{}`, `"status":"deactivated"`, 200},
	} {
		before := f.guards + f.calls
		postRaw(t, s, "", op.path, "unauth", []byte(op.body), 401)
		badBodies := []string{"null", "[]", `{`, `{} {}`, `{"extra":true}`, strings.Repeat(" ", 65537) + op.body}
		if op.path == "/v1/users" {
			badBodies = append(badBodies, `{"email":"person@example.test","display_name":"`+string([]byte{0xff})+`"}`)
			badBodies = append(badBodies, `{"email":null,"display_name":"Person"}`, `{"email":"a@b.test","email":"x@y.test","display_name":"Person"}`, `{"organization_id":null,"email":"a@b.test","display_name":"Person"}`)
		}
		if op.path == "/v1/organizations" {
			badBodies = append(badBodies, `{"name":"`+string([]byte{0xff})+`","slug":"example"}`)
			badBodies = append(badBodies, `{"name":null,"slug":"x"}`, `{"name":"a","name":"b","slug":"x"}`)
		}
		for i, bad := range badBodies {
			postRaw(t, s, secret, op.path, fmt.Sprintf("bad-membership-%d", i), []byte(bad), 400)
		}
		if f.guards+f.calls != before {
			t.Fatal("invalid membership body reached service")
		}
		out := postRaw(t, s, secret, op.path, "valid-membership", []byte(op.body), op.status)
		if !strings.Contains(out, op.field) || f.guards+f.calls != before+2 || f.actor.KeyID == "" || f.actor.TenantID == "" {
			t.Fatal("focused membership DTO or actor lost")
		}
		for i, ec := range []struct {
			err    error
			status int
		}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private membership SQL"), 500}} {
			for _, stage := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if stage == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				calls := f.calls
				out := postRaw(t, s, secret, op.path, fmt.Sprintf("%s-membership-%d", stage, i), []byte(op.body), ec.status)
				if strings.Contains(out, "private membership SQL") || strings.Contains(out, "person@example.test") || stage == "guard" && calls != f.calls {
					t.Fatal("unsafe membership failure")
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
	}
	if f.org.Name != "Example" || f.user.OrganizationID != "org" || f.id != "user" {
		t.Fatal("membership input mapping lost")
	}
	before := f.guards + f.calls
	postRaw(t, s, secret, "/v1/users/user/deactivate", "omitted-membership-body", nil, 200)
	if f.guards+f.calls != before+2 {
		t.Fatal("omitted deactivation body compatibility lost")
	}
}
