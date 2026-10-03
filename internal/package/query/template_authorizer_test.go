package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestTemplateAuthorizerRequiresTenantWideReportGrant(t *testing.T) {
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "ten_1", "report:read", true}, {"tenant", "ten_other", "report:read", false}, {"product", "prod_1", "report:read", false}, {"release", "rel_1", "report:read", false}, {"tenant", "ten_1", "package:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			for _, request := range []application.AuthorizationRequest{{Scope: "report:read", ScopeOnly: true}, {Scope: "report:read", TenantWide: true}} {
				err := NewTemplateAuthorizer().Authorize(t.Context(), actor, request)
				if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestQTemplateAuthorizerRequiresTenantWideWriteGrant(t *testing.T) {
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "tenant", "package:write", true}, {"tenant", "other", "package:write", false}, {"product", "product", "package:write", false}, {"release", "release", "package:write", false}, {"tenant", "tenant", "package:read", false}, {"", "", "admin", true},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := NewQuestionnaireTemplateAuthorizer().Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "package:write", TenantWide: true})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal("incorrect template authority", err)
			}
		})
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	for _, r := range []application.AuthorizationRequest{{Scope: "report:read", TenantWide: true}, {Scope: "package:write", TenantWide: true, Resources: application.ResourceReferences{ProductID: "p"}}, {Scope: "package:write"}} {
		if err := NewQuestionnaireTemplateAuthorizer().Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("invalid authorization coordinates accepted", err)
		}
	}
}
