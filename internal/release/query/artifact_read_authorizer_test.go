package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestArtifactReadAuthorizerRequiresCurrentReadAssociation(t *testing.T) {
	reader := &artifactPointReaderStub{point: ArtifactPoint{Artifact: releasedomain.Artifact{ID: "artifact", TenantID: "ten_1"}, Visible: true}}
	auth, err := NewArtifactReadAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	a := catalogActor("evidence:read", "product", "product", "evidence:read")
	r := application.AuthorizationRequest{Scope: "evidence:read", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	if err := auth.Authorize(t.Context(), a, r); err != nil || reader.request.TenantID != "ten_1" || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "product" {
		t.Fatal("artifact read grant changed", reader.request, err)
	}
	reader.point.Visible = false
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unlinked association accepted", err)
	}
	reader.point.Visible = true
	reader.point.Artifact.TenantID = "other"
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign artifact accepted", err)
	}
	a.ResourceGrants = nil
	before := reader.calls
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatal("removed grants read artifact", err)
	}
	for _, bad := range []application.AuthorizationRequest{{Scope: "evidence:write", Resources: r.Resources}, {Scope: "evidence:read", ScopeOnly: true}, {Scope: "evidence:read", TenantWide: true, Resources: r.Resources}, {Scope: "evidence:read"}, {Scope: "evidence:read", Resources: application.ResourceReferences{ArtifactID: "artifact", ReleaseID: "release"}}} {
		if err := auth.Authorize(t.Context(), a, bad); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("invalid artifact auth accepted", bad, err)
		}
	}
	a.KeyID = "key"
	if err := auth.Authorize(t.Context(), a, r); err != nil {
		t.Fatal("scoped key denied", err)
	}
	if _, err := NewArtifactReadAuthorizer(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
}
