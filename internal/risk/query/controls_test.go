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

type controlsReaderFake struct {
	frameworks appquery.Result[riskdomain.ControlFramework]
	control    riskdomain.SecurityControl
	request    FrameworkPageRequest
	pageCalls  int
	pointCalls int
}

func (f *controlsReaderFake) PageFrameworks(_ context.Context, request FrameworkPageRequest) (appquery.Result[riskdomain.ControlFramework], error) {
	f.pageCalls++
	f.request = request
	return f.frameworks, nil
}

func (f *controlsReaderFake) GetControl(_ context.Context, _, _ string) (riskdomain.SecurityControl, error) {
	f.pointCalls++
	return f.control, nil
}

func TestControlsQueriesRequireTenantWideHumanGrant(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &controlsReaderFake{
		frameworks: appquery.Result[riskdomain.ControlFramework]{Items: []riskdomain.ControlFramework{{ID: "fw_1", TenantID: "ten_1", Name: "Framework", Slug: "framework", Version: "1", Status: "active", CreatedAt: now}}},
		control:    riskdomain.SecurityControl{ID: "ctrl_1", TenantID: "ten_1", FrameworkID: "fw_1", Code: "BUILD", Title: "Build evidence", CreatedAt: now},
	}
	service, err := NewControls(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"controls:read"}}}}
	if _, err := service.ListFrameworksPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("product grant page error=%v", err)
	}
	if _, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1"); !errors.Is(err, application.ErrForbidden) || reader.pageCalls != 0 || reader.pointCalls != 0 {
		t.Fatalf("product grant point error=%v reader=%#v", err, reader)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_other", Scopes: []string{"controls:read"}}
	if _, err := service.ListFrameworksPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign tenant grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "ten_1"
	result, err := service.ListFrameworksPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || reader.request.TenantID != actor.TenantID {
		t.Fatalf("tenant page=%#v request=%#v error=%v", result, reader.request, err)
	}
	control, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1")
	if err != nil || control.ID != "ctrl_1" {
		t.Fatalf("tenant point=%#v error=%v", control, err)
	}
	actor.ResourceGrants = nil
	if _, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1"); !errors.Is(err, application.ErrForbidden) || reader.pointCalls != 1 {
		t.Fatalf("revoked grant error=%v calls=%d", err, reader.pointCalls)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"controls:read"}}
	if _, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1"); err != nil || reader.pointCalls != 2 {
		t.Fatalf("scoped credential error=%v calls=%d", err, reader.pointCalls)
	}
}

func TestControlsQueriesRejectUnsafeProjections(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	framework := riskdomain.ControlFramework{ID: "fw_1", TenantID: "ten_1", Name: "Framework", Slug: "framework", Version: "1", Status: "active", CreatedAt: now}
	reader := &controlsReaderFake{frameworks: appquery.Result[riskdomain.ControlFramework]{Items: []riskdomain.ControlFramework{framework}}, control: riskdomain.SecurityControl{ID: "ctrl_1", TenantID: "ten_1", FrameworkID: "fw_1", CreatedAt: now}}
	service, err := NewControls(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"controls:read"}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	reader.frameworks.Items[0].TenantID = "ten_other"
	if _, err := service.ListFrameworksPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign framework error=%v", err)
	}
	reader.frameworks.Items[0] = framework
	reader.frameworks.Next = &appquery.SortKey{ID: "wrong", Value: now.Format(time.RFC3339Nano)}
	if _, err := service.ListFrameworksPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong cursor error=%v", err)
	}
	reader.control.FrameworkID = ""
	if _, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing control parent error=%v", err)
	}
	reader.control.FrameworkID = "fw_1"
	reader.control.TenantID = "ten_other"
	if _, err := service.GetSecurityControl(t.Context(), actor, "ctrl_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign control error=%v", err)
	}
	if _, err := NewControls(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
}

func TestControlTemplateCatalogPreservesScopeAndReturnsIndependentValues(t *testing.T) {
	service, err := NewControls(&controlsReaderFake{})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"controls:read"}}}}
	packs, err := service.ListTemplatePacks(t.Context(), actor)
	if err != nil || len(packs) != 4 || packs[0].Slug != "evydence-cra-readiness" || len(packs[0].Controls) == 0 {
		t.Fatalf("template packs=%#v error=%v", packs, err)
	}
	packs[0].Controls[0].EvidenceRequirements[0].Type = "corrupted"
	again, err := service.ListTemplatePacks(t.Context(), actor)
	if err != nil || again[0].Controls[0].EvidenceRequirements[0].Type != "sbom" {
		t.Fatalf("template catalog was mutated: packs=%#v error=%v", again, err)
	}
	for _, denied := range []identitydomain.Actor{
		{TenantID: "ten_1", Scopes: []string{"controls:read"}},
		{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}},
	} {
		if _, err := service.ListTemplatePacks(t.Context(), denied); err == nil {
			t.Fatalf("unauthorized template list accepted: %#v", denied)
		}
	}
}
