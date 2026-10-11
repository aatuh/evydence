package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestEvidenceVerificationAuthorizerScopesAndGrants(t *testing.T) {
	authorizer := NewEvidenceVerificationAuthorizer()
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}
	for _, tc := range []struct {
		kind, id string
		allowed  bool
	}{
		{"tenant", "tenant", true}, {"product", "product", true}, {"project", "project", true}, {"release", "release", true},
		{"tenant", "other", false}, {"release", "other", false}, {"build", "build", false}, {"deployment", "deployment", false},
	} {
		t.Run(tc.kind+tc.id, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{"verify:read"}}}}
			err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal(err)
			}
			actor.ResourceGrants = nil
			if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, Resources: refs}); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant", err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, TenantWide: true}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []application.AuthorizationRequest{
		{Scope: "evidence:read", Resources: refs}, {Action: authz.ActionEvidenceVerify, ScopeOnly: true, Resources: refs},
		{Action: authz.ActionEvidenceVerify, TenantWide: true, Resources: refs}, {Action: authz.ActionEvidenceVerify, Resources: application.ResourceReferences{EnvironmentID: "env"}},
	} {
		if err := authorizer.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(request, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, ScopeOnly: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
