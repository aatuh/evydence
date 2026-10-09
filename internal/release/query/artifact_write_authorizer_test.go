package query

import (
	"errors"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestArtifactSecurityWriteAuthorizerKeepsScopeAndAssociationPolicy(t *testing.T) {
	reader := &buildArtifactPointReaderFake{point: ArtifactPoint{Artifact: releasedomain.Artifact{ID: "artifact", TenantID: "ten_1"}, Visible: true}}
	auth, err := NewArtifactSecurityWriteAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	a := catalogActor("security:write", "product", "product", "security:write")
	r := application.AuthorizationRequest{Scope: "security:write", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	if err := auth.Authorize(t.Context(), a, r); err != nil || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "product" {
		t.Fatal(reader.request, err)
	}
	reader.point.Visible = false
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unlinked artifact accepted", err)
	}
	reader.point.Visible = true
	a.ResourceGrants[0].Scopes = []string{"evidence:write"}
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong grant scope accepted", err)
	}
	a.ResourceGrants[0].Scopes = []string{"security:write"}
	r.Scope = "evidence:write"
	if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("evidence scope accepted", err)
	}
	if _, err := NewArtifactSecurityWriteAuthorizer(nil); err == nil {
		t.Fatal("missing reader accepted")
	}
}

func TestArtifactWriteAuthorizerRequiresCurrentDuplicateGrant(t *testing.T) {
	reader := &buildArtifactPointReaderFake{point: ArtifactPoint{
		Artifact: releasedomain.Artifact{ID: "art_1", TenantID: "ten_1"}, Visible: true,
	}}
	authorizer, err := NewArtifactWriteAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := catalogActor("evidence:write", "product", "prod_1", "evidence:write")
	if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "evidence:write", ScopeOnly: true}); err != nil {
		t.Fatalf("scope-only create denied: %v", err)
	}
	existing := application.AuthorizationRequest{Scope: "evidence:write", Resources: application.ResourceReferences{ArtifactID: "art_1"}}
	if err := authorizer.Authorize(t.Context(), actor, existing); err != nil {
		t.Fatalf("linked duplicate denied: %v", err)
	}
	if reader.request.TenantID != "ten_1" || reader.request.ID != "art_1" || reader.request.TenantWide ||
		len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("duplicate grant query=%#v", reader.request)
	}
	reader.point.Visible = false
	if err := authorizer.Authorize(t.Context(), actor, existing); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("unlinked duplicate err=%v, want forbidden", err)
	}
	reader.point.Visible = true
	key := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:write"}}
	if err := authorizer.Authorize(t.Context(), key, existing); err != nil {
		t.Fatalf("scoped key denied duplicate: %v", err)
	}
	if _, err := NewArtifactWriteAuthorizer(nil); err == nil {
		t.Fatal("nil artifact association reader accepted")
	}
}
