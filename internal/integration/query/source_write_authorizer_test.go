package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSourceWriteAuthorizerRequiresCurrentProjectOrTenantGrant(t *testing.T) {
	auth := NewSourceWriteAuthorizer()
	for _, tc := range []struct {
		kind, id         string
		scoped, detached bool
	}{{"tenant", "tenant", true, true}, {"product", "product", true, false}, {"project", "project", true, false}, {"project", "other", false, false}, {"release", "release", false, false}, {"", "other", false, false}} {
		a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"source:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{"source:write"}}}}
		for _, detached := range []bool{false, true} {
			r := application.AuthorizationRequest{Scope: "source:write", TenantWide: detached}
			if !detached {
				r.Resources = application.ResourceReferences{ProductID: "product", ProjectID: "project"}
			}
			err := auth.Authorize(t.Context(), a, r)
			allow := tc.scoped
			if detached {
				allow = tc.detached
			}
			if allow && err != nil || !allow && !errors.Is(err, application.ErrForbidden) {
				t.Fatal(tc, detached, err)
			}
		}
		a.ResourceGrants = nil
		if err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "source:write", TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("revoked grant remained authorized", err)
		}
	}
	for _, a := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, {TenantID: "tenant", CollectorID: "collector", Scopes: []string{"admin"}}} {
		if err := auth.Authorize(t.Context(), a, application.AuthorizationRequest{Scope: "source:write", TenantWide: true}); err != nil {
			t.Fatal(err)
		}
	}
}
