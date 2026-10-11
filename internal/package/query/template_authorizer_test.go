package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
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
			for _, request := range []application.AuthorizationRequest{{Action: authz.ActionReportTemplatesManage, ScopeOnly: true}, {Action: authz.ActionReportTemplatesManage, TenantWide: true}} {
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
			for _, policy := range []struct {
				authorizer application.Authorizer
				action     authz.Action
			}{
				{NewQuestionnaireTemplateAuthorizer(), authz.ActionQuestionnaireTemplatesManage},
				{NewRedactionProfileAuthorizer(), authz.ActionRedactionProfilesManage},
			} {
				for _, request := range []application.AuthorizationRequest{{Action: policy.action, TenantWide: true}, {Action: policy.action, ScopeOnly: true}} {
					err := policy.authorizer.Authorize(t.Context(), a, request)
					if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
						t.Fatal("incorrect tenant-wide package authority", err)
					}
				}
			}
		})
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	for _, policy := range []struct {
		authorizer application.Authorizer
		action     authz.Action
	}{
		{NewQuestionnaireTemplateAuthorizer(), authz.ActionQuestionnaireTemplatesManage},
		{NewRedactionProfileAuthorizer(), authz.ActionRedactionProfilesManage},
	} {
		for _, r := range []application.AuthorizationRequest{
			{Action: authz.ActionReportTemplatesManage, TenantWide: true},
			{Action: policy.action, TenantWide: true, Resources: application.ResourceReferences{ProductID: "p"}},
			{Action: policy.action}, {Action: policy.action, Scope: "package:write", TenantWide: true},
		} {
			if err := policy.authorizer.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("invalid authorization coordinates accepted", err)
			}
		}
	}
}
