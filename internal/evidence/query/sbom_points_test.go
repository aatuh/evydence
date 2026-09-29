package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomPointReaderStub struct {
	tenantID string
	id       string
	point    SBOMPoint
	called   int
}

func (s *sbomPointReaderStub) GetSBOMPoint(_ context.Context, tenantID, id string) (SBOMPoint, error) {
	s.called++
	s.tenantID, s.id = tenantID, id
	return s.point, nil
}

func TestSBOMPointQueryChecksTenantGrantAndProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &sbomPointReaderStub{point: SBOMPoint{ProductID: "prod_1", SBOM: evidencedomain.SBOM{
		ID: "sbom_1", TenantID: "ten_1", EvidenceID: "ev_1", ReleaseID: "rel_1",
		Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1,
		Components: []evidencedomain.SBOMComponent{{Name: "openssl", PURL: "pkg:generic/openssl@3"}}, CreatedAt: now,
	}}}
	service, err := NewSBOMPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"evidence:read"}}}}
	result, err := service.GetSBOM(t.Context(), actor, " sbom_1 ")
	if err != nil || result.ID != "sbom_1" || reader.tenantID != "ten_1" || reader.id != "sbom_1" {
		t.Fatalf("scoped SBOM=%#v reader=%#v error=%v", result, reader, err)
	}
	reader.point.SBOM.TenantID = "ten_other"
	if _, err := service.GetSBOM(t.Context(), actor, "sbom_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.point.SBOM.TenantID = "ten_1"
	reader.point.ProductID = "prod_other"
	if _, err := service.GetSBOM(t.Context(), actor, "sbom_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant error=%v", err)
	}
	reader.point.ProductID = "prod_1"
	reader.point.SBOM.ComponentCount = 2
	if _, err := service.GetSBOM(t.Context(), actor, "sbom_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("component count mismatch error=%v", err)
	}
	reader.point.SBOM.ComponentCount = 1
	reader.point.SBOM.Components[0].Name = ""
	if _, err := service.GetSBOM(t.Context(), actor, "sbom_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unnamed component error=%v", err)
	}
	reader.point.SBOM.Components[0].Name = "openssl"
	noGrant := actor
	noGrant.ResourceGrants = nil
	before := reader.called
	if _, err := service.GetSBOM(t.Context(), noGrant, "sbom_1"); !errors.Is(err, application.ErrForbidden) || reader.called != before+1 {
		t.Fatalf("no-grant error=%v calls=%d", err, reader.called)
	}
	noScope := actor
	noScope.Scopes = nil
	before = reader.called
	if _, err := service.GetSBOM(t.Context(), noScope, "sbom_1"); !errors.Is(err, application.ErrForbidden) || reader.called != before {
		t.Fatalf("no-scope error=%v calls=%d", err, reader.called)
	}
}
