package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestGraphAuthorizerRequiresCurrentMatchingScope(t *testing.T) {
	p := NewGraphSnapshotAuthorizer()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:read"}}
	r := application.AuthorizationRequest{Scope: "evidence:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	for _, test := range []struct {
		kind, id, scope string
		allow           bool
	}{{"tenant", "tenant", "evidence:read", true}, {"product", "product", "evidence:read", true}, {"release", "release", "evidence:read", true}, {"product", "other", "evidence:read", false}, {"release", "other", "evidence:read", false}, {"project", "project", "evidence:read", false}, {"tenant", "other", "evidence:read", false}, {"product", "product", "package:read", false}} {
		a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: test.kind, ResourceID: test.id, Scopes: []string{test.scope}}}
		err := p.Authorize(t.Context(), a, r)
		if test.allow && err != nil || !test.allow && !errors.Is(err, application.ErrForbidden) {
			t.Fatal("graph grant mismatch", test, err)
		}
	}
	a.ResourceGrants = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grants accepted", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("scoped API key rejected", err)
	}
	r.Resources.ProjectID = "project"
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unrelated graph coordinate accepted", err)
	}
}
