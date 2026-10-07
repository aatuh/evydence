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

type roleBindingHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	input            identityapp.CreateRoleBindingInput
	guardErr, runErr error
}

func (f *roleBindingHTTPFake) AuthorizeCreateRoleBinding(_ context.Context, a identitydomain.Actor, in identityapp.CreateRoleBindingInput) error {
	f.guards++
	f.actor, f.input = a, in
	return f.guardErr
}
func (f *roleBindingHTTPFake) CreateRoleBinding(_ context.Context, a identitydomain.Actor, in identityapp.CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	f.calls++
	f.actor, f.input = a, in
	return identitydomain.RoleBinding{ID: "binding", TenantID: a.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role, ResourceType: in.ResourceType, ResourceID: in.ResourceID, SchemaVersion: identitydomain.RoleBindingSchemaVersion, CreatedAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)}, f.runErr
}
func TestRoleBindingHTTPFocusedCommandMapsDTOAndRejectsAmbiguousInput(t *testing.T) {
	base, secret := testServer(t)
	f := &roleBindingHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{RoleBindingCommands: f}); err == nil {
		t.Fatal("role assignments retained Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{RoleBindingCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"subject_type":"user","subject_id":"user","role":"release_manager","resource_type":"product","resource_id":"product"}`
	postRaw(t, s, "", "/v1/role-bindings", "unauth", []byte(body), 401)
	badBodies := []string{"null", "[]", `{`, `{} {}`, `{"subject_type":"user","subject_id":"user","role":"release_manager","extra":true}`, `{"subject_type":"user","subject_id":"user","role":"release_manager","role":"tenant_admin"}`, strings.Repeat(" ", 65537) + body, `{"subject_type":"user","subject_id":"` + string([]byte{0xff}) + `","role":"collector"}`}
	for _, field := range []string{"subject_type", "subject_id", "role", "resource_type", "resource_id"} {
		badBodies = append(badBodies, `{"`+field+`":null}`)
	}
	for i, bad := range badBodies {
		postRaw(t, s, secret, "/v1/role-bindings", fmt.Sprintf("bad-role-%d", i), []byte(bad), 400)
	}
	if f.calls+f.guards != 0 {
		t.Fatal("invalid role body reached command")
	}
	out := postRaw(t, s, secret, "/v1/role-bindings", "valid-role", []byte(body), 201)
	if f.calls != 1 || f.guards != 1 || f.actor.KeyID == "" || f.actor.TenantID == "" || f.input.Role != "release_manager" || f.input.ResourceID != "product" || f.input.SubjectID != "user" {
		t.Fatal("role request/actor mapping lost")
	}
	for _, field := range []string{`"id":"binding"`, `"subject_type":"user"`, `"subject_id":"user"`, `"role":"release_manager"`, `"resource_type":"product"`, `"resource_id":"product"`, `"schema_version":"role-binding.v1.0.0"`} {
		if !strings.Contains(out, field) {
			t.Fatal("public role field lost", field)
		}
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{identityapp.ErrValidation, 400}, {identityapp.ErrNotFound, 404}, {identityapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private role storage"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/role-bindings", fmt.Sprintf("%s-role-%d", stage, i), []byte(body), ec.status)
			if strings.Contains(out, "private role storage") || strings.Contains(out, `"id":"binding"`) || stage == "guard" && f.calls != before {
				t.Fatal("unsafe role failure")
			}
		}
	}
}
