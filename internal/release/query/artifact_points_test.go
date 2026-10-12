package query

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type artifactPointReaderStub struct {
	point   ArtifactPoint
	request ArtifactReadRequest
	calls   int
	before  func()
}

func (s *artifactPointReaderStub) GetArtifactPoint(_ context.Context, request ArtifactReadRequest) (ArtifactPoint, error) {
	s.calls++
	s.request = request
	if s.before != nil {
		s.before()
	}
	return s.point, nil
}

func TestArtifactPointReadRejectsCancellationAfterFilteredRead(t *testing.T) {
	reader := &artifactPointReaderStub{point: ArtifactPoint{Artifact: releasedomain.Artifact{
		ID: "artifact", TenantID: "tenant", Name: "private artifact", MediaType: "text/plain", Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
	}, Visible: true}}
	service, err := NewArtifactPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader.before = cancel
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}
	artifact, err := service.GetArtifact(ctx, actor, "artifact")
	if !errors.Is(err, context.Canceled) || artifact.ID != "" || reader.calls != 1 {
		t.Fatal("canceled read returned private metadata", artifact, err, reader.calls)
	}
}

func TestArtifactPointAssociationProofIsBoundToExactReadFilters(t *testing.T) {
	reader := &artifactPointReaderStub{point: ArtifactPoint{Artifact: releasedomain.Artifact{
		ID: "artifact", TenantID: "tenant", Name: "private artifact", MediaType: "text/plain", Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
	}, Visible: true}}
	service, err := NewArtifactPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "original", Scopes: []string{"evidence:read"}}}}
	reader.before = func() { actor.ResourceGrants[0].ResourceID = "different" }
	artifact, err := service.GetArtifact(t.Context(), actor, "artifact")
	if !errors.Is(err, application.ErrForbidden) || artifact.ID != "" || reader.calls != 1 || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "original" {
		t.Fatal("association proof reused for different grants", artifact, reader.request, err)
	}
}

func TestArtifactPointReadChecksScopeGrantAndTenant(t *testing.T) {
	reader := &artifactPointReaderStub{point: ArtifactPoint{Artifact: releasedomain.Artifact{
		ID: "art_1", TenantID: "ten_1", Name: "artifact", MediaType: "application/octet-stream",
		Digest: "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", Size: 1,
		CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}, Visible: true}}
	service, err := NewArtifactPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"evidence:read"}}}}
	artifact, err := service.GetArtifact(t.Context(), actor, " art_1 ")
	if err != nil || artifact.ID != "art_1" || reader.request.ID != "art_1" || reader.request.TenantWide ||
		len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("scoped artifact=%#v request=%#v error=%v", artifact, reader.request, err)
	}
	reader.point.Visible = false
	if _, err := service.GetArtifact(t.Context(), actor, "art_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("unlinked grant error=%v", err)
	}
	reader.point.Visible = true
	reader.point.Artifact.TenantID = "ten_2"
	if _, err := service.GetArtifact(t.Context(), actor, "art_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.point.Artifact.TenantID = "ten_1"
	noGrant := actor
	noGrant.ResourceGrants = nil
	before := reader.calls
	if _, err := service.GetArtifact(t.Context(), noGrant, "art_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("no grant error=%v calls=%d", err, reader.calls)
	}
	noScope := actor
	noScope.Scopes = nil
	if _, err := service.GetArtifact(t.Context(), noScope, "art_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("no scope error=%v", err)
	}
	key := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifact(t.Context(), key, "art_1"); err != nil || !reader.request.TenantWide {
		t.Fatalf("key read error=%v request=%#v", err, reader.request)
	}
}
