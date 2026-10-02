package query

import (
	"context"
	"errors"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildArtifactPointReaderFake struct {
	request ArtifactReadRequest
	point   ArtifactPoint
}

func (r *buildArtifactPointReaderFake) GetArtifactPoint(_ context.Context, request ArtifactReadRequest) (ArtifactPoint, error) {
	r.request = request
	return r.point, nil
}

func TestBuildAuthorizerChecksOutputArtifactAgainstCurrentGrantAssociations(t *testing.T) {
	reader := &buildArtifactPointReaderFake{point: ArtifactPoint{
		Artifact: releasedomain.Artifact{ID: "art_1", TenantID: "ten_1"}, Visible: true,
	}}
	authorizer, err := NewBuildAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	productActor := catalogActor("build:write", "product", "prod_1", "build:write")
	parent := application.AuthorizationRequest{Scope: "build:write", Resources: application.ResourceReferences{
		ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1",
	}}
	if err := authorizer.Authorize(t.Context(), productActor, parent); err != nil {
		t.Fatalf("product grant denied build parent: %v", err)
	}
	artifact := application.AuthorizationRequest{Scope: "build:write", Resources: application.ResourceReferences{ArtifactID: "art_1"}}
	if err := authorizer.Authorize(t.Context(), productActor, artifact); err != nil {
		t.Fatalf("linked artifact denied: %v", err)
	}
	if reader.request.TenantID != "ten_1" || reader.request.ID != "art_1" || reader.request.TenantWide ||
		len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("artifact grant query=%#v", reader.request)
	}
	reader.point.Visible = false
	if err := authorizer.Authorize(t.Context(), productActor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("unlinked artifact err=%v, want forbidden", err)
	}
	reader.point.Visible = true
	reader.point.Artifact.TenantID = "ten_other"
	if err := authorizer.Authorize(t.Context(), productActor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("hostile artifact projection err=%v, want forbidden", err)
	}
	reader.point.Artifact.TenantID = "ten_1"
	wrongGrant := catalogActor("build:write", "product", "prod_other", "build:write")
	if err := authorizer.Authorize(t.Context(), wrongGrant, parent); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant authorized parent: %v", err)
	}
	key := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"build:write"}}
	if err := authorizer.Authorize(t.Context(), key, artifact); err != nil {
		t.Fatalf("scoped key denied artifact: %v", err)
	}
	if _, err := NewBuildAuthorizer(nil); err == nil {
		t.Fatal("nil artifact reader accepted")
	}
}

func TestBuildAttestationAuthorizerRequiresResolvedParentGrants(t *testing.T) {
	reader := &buildArtifactPointReaderFake{}
	auth, err := NewBuildAttestationAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	r := application.AuthorizationRequest{Scope: "build:write", Resources: application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "build_1"}}
	actor := catalogActor("build:write", "project", "proj_1", "build:write")
	if err := auth.Authorize(t.Context(), actor, r); err != nil {
		t.Fatal("resolved build denied", err)
	}
	actor.ResourceGrants = nil
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revoked parent grant accepted", err)
	}
	actor = catalogActor("build:write", "project", "proj_other", "build:write")
	if err := auth.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign parent grant accepted", err)
	}
	actor = catalogActor("build:write", "project", "proj_1", "build:write")
	for _, mutate := range []func(*application.ResourceReferences){func(v *application.ResourceReferences) { v.ProductID = "" }, func(v *application.ResourceReferences) { v.ProjectID = "" }, func(v *application.ResourceReferences) { v.ReleaseID = "" }, func(v *application.ResourceReferences) { v.ArtifactID = "artifact" }, func(v *application.ResourceReferences) { v.DeploymentID = "deployment" }} {
		bad := r
		mutate(&bad.Resources)
		if err := auth.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("incomplete or unrelated reference accepted", bad, err)
		}
	}
}
