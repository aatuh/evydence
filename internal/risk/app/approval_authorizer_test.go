package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestApprovalWriteAuthorizerRequiresCurrentSubjectOrTenantGrant(t *testing.T) {
	auth := NewApprovalWriteAuthorizer()
	for _, test := range []struct {
		typ, id string
		wide    bool
		want    error
	}{
		{"product", "product", false, nil}, {"release", "release", false, nil},
		{"product", "other", false, application.ErrForbidden}, {"project", "project", false, application.ErrForbidden},
		{"tenant", "tenant", false, nil}, {"tenant", "other", false, application.ErrForbidden},
		{"tenant", "tenant", true, nil}, {"product", "product", true, application.ErrForbidden},
		{"release", "release", true, application.ErrForbidden}, {"tenant", "other", true, application.ErrForbidden},
	} {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeReleaseWrite}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: test.typ, ResourceID: test.id, Scopes: []string{ScopeReleaseWrite}}}}
		r := application.AuthorizationRequest{Scope: ScopeReleaseWrite, TenantWide: test.wide}
		if !test.wide {
			r.Resources = application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
		}
		if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, test.want) {
			t.Fatal(test, err)
		}
	}
	key := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeReleaseWrite}}
	if err := auth.Authorize(t.Context(), key, application.AuthorizationRequest{Scope: ScopeReleaseWrite, TenantWide: true}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []application.AuthorizationRequest{{Scope: ScopeEvidenceWrite, ScopeOnly: true}, {Scope: ScopeReleaseWrite}, {Scope: ScopeReleaseWrite, TenantWide: true, Resources: application.ResourceReferences{ProductID: "product"}}, {Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: "product", ArtifactID: "artifact"}}} {
		if err := auth.Authorize(t.Context(), key, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unrelated capability accepted", r, err)
		}
	}
}
