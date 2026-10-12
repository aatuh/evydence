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

type contractPointReaderStub struct {
	point        OpenAPIContractPoint
	tenantID, id string
	calls        int
}

func (s *contractPointReaderStub) GetOpenAPIContractPoint(_ context.Context, tenantID, id string) (OpenAPIContractPoint, error) {
	s.calls++
	s.tenantID, s.id = tenantID, id
	return s.point, nil
}

func TestOpenAPIContractPointScopeGrantAndTenant(t *testing.T) {
	reader := &contractPointReaderStub{point: OpenAPIContractPoint{Contract: evidencedomain.OpenAPIContract{
		ID: "con_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", EvidenceID: "ev_1",
		Version: "1.0", Hash: "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		PathCount: 1, Operations: []evidencedomain.OpenAPIOperation{{Path: "/v1/items", Method: "GET"}},
		CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}}}
	service, err := NewOpenAPIContractPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"evidence:read"}}}}
	contract, err := service.GetOpenAPIContract(t.Context(), actor, " con_1 ")
	if err != nil || contract.ID != "con_1" || reader.tenantID != "ten_1" || reader.id != "con_1" {
		t.Fatalf("contract=%#v reader=%#v error=%v", contract, reader, err)
	}
	actor.ResourceGrants[0].ResourceType, actor.ResourceGrants[0].ResourceID = "release", "rel_1"
	if _, err := service.GetOpenAPIContract(t.Context(), actor, "con_1"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.GetOpenAPIContract(t.Context(), actor, "con_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceType, actor.ResourceGrants[0].ResourceID = "tenant", "ten_1"
	reader.point.Contract.TenantID = "ten_other"
	if _, err := service.GetOpenAPIContract(t.Context(), actor, "con_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.point.Contract.TenantID = "ten_1"
	reader.point.Contract.Hash = "invalid"
	if _, err := service.GetOpenAPIContract(t.Context(), actor, "con_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("invalid hash error=%v", err)
	}
	noScope := actor
	noScope.Scopes = nil
	before := reader.calls
	if _, err := service.GetOpenAPIContract(t.Context(), noScope, "con_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("missing scope error=%v calls=%d", err, reader.calls)
	}
}
