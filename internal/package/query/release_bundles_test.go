package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type releaseBundleReaderStub struct {
	point ReleaseBundlePoint
	calls int
}

func (r *releaseBundleReaderStub) GetReleaseBundlePoint(_ context.Context, _, _ string) (ReleaseBundlePoint, error) {
	r.calls++
	return r.point, nil
}

func TestReleaseBundleQueryChecksTenantParentAndGrant(t *testing.T) {
	state, _ := packagedomain.ParseBundleState(packagedomain.BundleStateGeneratedValue)
	reader := &releaseBundleReaderStub{point: ReleaseBundlePoint{
		Bundle: packagedomain.ReleaseBundle{ID: "bun_1", TenantID: "ten_1", ReleaseID: "rel_1", State: state,
			Manifest: map[string]any{"private": "manifest"}, ManifestHash: "sha256:hash", SignatureRefs: []string{}, CreatedAt: time.Now()},
		ProductID: "prod_1",
	}}
	service, err := NewReleaseBundles(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"bundle:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"bundle:read"}}}}
	if bundle, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); err != nil || bundle.Manifest["private"] != "manifest" {
		t.Fatalf("product grant bundle=%#v error=%v", bundle, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"bundle:read"}}
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{"bundle:read"}}
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); err != nil {
		t.Fatalf("tenant grant error=%v", err)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"bundle:read"}}
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); err != nil {
		t.Fatalf("issued credential error=%v", err)
	}
	reader.point.Bundle.TenantID = "ten_other"
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); !errors.Is(err, ErrReleaseBundleProjection) {
		t.Fatalf("foreign projection error=%v", err)
	}
}

func TestReleaseBundleQueryRejectsInvalidActorAndIDBeforeReading(t *testing.T) {
	reader := &releaseBundleReaderStub{}
	service, _ := NewReleaseBundles(reader)
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"bundle:read"}}
	if _, err := service.GetReleaseBundle(t.Context(), actor, " "); !errors.Is(err, ErrReleaseBundleNotFound) {
		t.Fatalf("blank id error=%v", err)
	}
	actor.Scopes = nil
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("scope error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.GetReleaseBundle(t.Context(), actor, "bun_1"); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("identity error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid calls reached reader: %d", reader.calls)
	}
}
