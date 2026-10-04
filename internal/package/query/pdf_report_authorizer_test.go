package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPDFReportAuthorizerRequiresCurrentMatchingGrant(t *testing.T) {
	p := NewPDFReportAuthorizer()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"report:read"}}
	r := application.AuthorizationRequest{Scope: "report:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	for _, test := range []struct {
		kind, id, scope string
		allow           bool
	}{{"tenant", "tenant", "report:read", true}, {"product", "product", "report:read", true}, {"release", "release", "report:read", true}, {"product", "other", "report:read", false}, {"release", "other", "report:read", false}, {"tenant", "other", "report:read", false}, {"project", "project", "report:read", false}, {"product", "product", "package:read", false}} {
		a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: test.kind, ResourceID: test.id, Scopes: []string{test.scope}}}
		err := p.Authorize(t.Context(), a, r)
		if test.allow && err != nil || !test.allow && !errors.Is(err, application.ErrForbidden) {
			t.Fatal("PDF grant mismatch", test, err)
		}
	}
	a.ResourceGrants = nil
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed PDF grants accepted", err)
	}
	a.KeyID = "key"
	if err := p.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("scoped PDF key rejected", err)
	}
	r.Resources.ProjectID = "project"
	if err := p.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unrelated PDF coordinate accepted", err)
	}
}
