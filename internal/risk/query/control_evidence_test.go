package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlEvidenceReaderStub struct {
	request ControlEvidencePageRequest
	result  appquery.Result[ControlEvidencePoint]
	calls   int
}

func (r *controlEvidenceReaderStub) PageControlEvidence(_ context.Context, request ControlEvidencePageRequest) (appquery.Result[ControlEvidencePoint], error) {
	r.calls++
	r.request = request
	return r.result, nil
}

func TestControlEvidenceQueryDerivesGrantsAndRejectsWidenedProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	point := ControlEvidencePoint{Link: riskdomain.ControlEvidence{ID: "link_1", TenantID: "ten_1", ControlID: "ctrl_1", EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom_1", ProductID: "prod_1", ReleaseID: "rel_1", Confidence: "high", SchemaVersion: "control-evidence.v1.0.0", CreatedAt: now}, ProductID: "prod_1", ReleaseID: "rel_1"}
	reader := &controlEvidenceReaderStub{result: appquery.Result[ControlEvidencePoint]{Items: []ControlEvidencePoint{point}}}
	service, err := NewControlEvidence(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"controls:read"}}}}
	result, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{ProductID: "prod_1"}, page, nil)
	if err != nil || len(result.Items) != 1 || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 {
		t.Fatalf("scoped list=%#v request=%#v error=%v", result, reader.request, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_other"
	if _, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("widened projection error=%v", err)
	}
	actor.ResourceGrants = nil
	reader.calls = 0
	if result, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, page, nil); err != nil || len(result.Items) != 0 || reader.calls != 0 {
		t.Fatalf("ungranted list=%#v calls=%d error=%v", result, reader.calls, err)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"controls:read"}}
	if _, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, page, nil); err != nil || !reader.request.TenantWide {
		t.Fatalf("credential list request=%#v error=%v", reader.request, err)
	}
}

func TestControlEvidenceQueryRejectsInvalidActorAndPage(t *testing.T) {
	reader := &controlEvidenceReaderStub{}
	service, _ := NewControlEvidence(reader)
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"controls:read"}}
	if _, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, appquery.PageRequest{}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, page, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	actor.KeyID, actor.Scopes = "key_1", nil
	if _, err := service.ListPage(t.Context(), actor, ControlEvidenceFilter{}, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid input reached reader %d times", reader.calls)
	}
}
