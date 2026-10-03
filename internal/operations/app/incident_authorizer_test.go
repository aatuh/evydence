package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestIncidentWriteAuthorizerRequiresCurrentScopeAndResourceGrants(t *testing.T) {
	auth := NewIncidentWriteAuthorizer()
	base := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}}
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}
	for _, kind := range []string{"tenant", "product", "project", "release"} {
		for _, scope := range []string{"incident:write", "admin", "*", "evidence:write"} {
			t.Run(kind+"/"+scope, func(t *testing.T) {
				a := base
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{scope}}}
				err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "incident:write", Resources: refs})
				if scope == "evidence:write" {
					if !errors.Is(err, application.ErrForbidden) {
						t.Fatal(err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				a.ResourceGrants[0].ResourceID = "other"
				if err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "incident:write", Resources: refs}); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("foreign grant", err)
				}
			})
		}
	}
	for _, a := range []identitydomain.Actor{base, {TenantID: "tenant", KeyID: "key", Scopes: []string{"incident:write"}}, {TenantID: "tenant", CollectorID: "collector", Scopes: []string{"incident:write"}}} {
		if err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "incident:write", ScopeOnly: true}); err != nil {
			t.Fatal(err)
		}
		err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "incident:write", Resources: refs})
		if a.UserID != "" {
			if !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	for _, request := range []application.AuthorizationRequest{
		{Scope: "release:write", ScopeOnly: true},
		{Scope: "incident:write", ScopeOnly: true, Resources: refs},
		{Scope: "incident:write", ScopeOnly: true, TenantWide: true},
		{Scope: "incident:write"},
		{Scope: "incident:write", Resources: application.ResourceReferences{ProductID: "product", ArtifactID: "artifact"}},
		{Scope: "incident:write", TenantWide: true, Resources: refs},
	} {
		a := base
		a.KeyID = "key"
		if err := auth.Authorize(t.Context(), a, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(request, err)
		}
	}
	tenantRequest := application.AuthorizationRequest{Scope: "incident:write", TenantWide: true}
	base.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"incident:write"}}}
	if err := auth.Authorize(t.Context(), base, tenantRequest); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	base.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"incident:write"}}}
	if err := auth.Authorize(t.Context(), base, tenantRequest); err != nil {
		t.Fatal(err)
	}
	base.Scopes = []string{"evidence:write"}
	if err := auth.Authorize(t.Context(), base, tenantRequest); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if err := auth.Authorize(t.Context(), identitydomain.Actor{}, tenantRequest); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal(err)
	}
	var missingContext context.Context
	if err := auth.Authorize(missingContext, base, tenantRequest); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := auth.Authorize(ctx, base, tenantRequest); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
