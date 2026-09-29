package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type marketplaceReaderStub struct {
	pageResult appquery.Result[experimentaldomain.MarketplaceCollector]
	point      MarketplaceCollectorPoint
	pageCalls  int
	getCalls   int
}

func (r *marketplaceReaderStub) PageMarketplaceCollectors(_ context.Context, request MarketplaceCollectorPageRequest) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	r.pageCalls++
	return r.pageResult, nil
}

func (r *marketplaceReaderStub) GetMarketplaceCollectorPoint(_ context.Context, _, _ string) (MarketplaceCollectorPoint, error) {
	r.getCalls++
	return r.point, nil
}

func TestMarketplaceCollectorQueryRequiresTenantGrantAndRejectsWrongTenantProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	collector := experimentaldomain.MarketplaceCollector{ID: "market_1", TenantID: "ten_1", Name: "Scanner", Provider: "example", Version: "1", Publisher: "example", ManifestHash: "sha256:manifest", State: "published", SchemaVersion: "marketplace-collector.v1.0.0", CreatedAt: now}
	reader := &marketplaceReaderStub{pageResult: appquery.Result[experimentaldomain.MarketplaceCollector]{Items: []experimentaldomain.MarketplaceCollector{collector}}, point: MarketplaceCollectorPoint{Collector: collector}}
	service, err := NewMarketplaceCollectors(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"collector:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"collector:read"}}}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("product grant list error=%v", err)
	}
	if _, err := service.Health(t.Context(), actor, collector.ID); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("product grant health error=%v", err)
	}
	if reader.pageCalls != 0 || reader.getCalls != 0 {
		t.Fatalf("ungranted reader calls: %#v", reader)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"collector:read"}}
	if result, err := service.ListPage(t.Context(), actor, page, nil); err != nil || len(result.Items) != 1 {
		t.Fatalf("tenant list=%#v error=%v", result, err)
	}
	reader.pageResult.Items[0].TenantID = "ten_2"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign page error=%v", err)
	}
	reader.point.Collector.TenantID = "ten_2"
	if _, err := service.Health(t.Context(), actor, collector.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign point error=%v", err)
	}
}

func TestMarketplaceCollectorQueryHealthStatusDoesNotTreatMissingReferencesAsVerified(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &marketplaceReaderStub{point: MarketplaceCollectorPoint{Collector: experimentaldomain.MarketplaceCollector{ID: "market_1", TenantID: "ten_1", Name: "Scanner", Provider: "example", Version: "1", Publisher: "example", ManifestHash: "sha256:manifest", SignatureID: "sig_1", SBOMID: "sbom_1", ScanID: "scan_1", State: "published", SchemaVersion: "marketplace-collector.v1.0.0", CreatedAt: now}}}
	service, _ := NewMarketplaceCollectors(reader, func() time.Time { return now })
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	report, err := service.Health(t.Context(), actor, "market_1")
	if err != nil || report.SupplyChainStatus != "failed" || len(report.Checks) != 4 {
		t.Fatalf("invalid references report=%#v error=%v", report, err)
	}
	reader.point.SignatureFound, reader.point.SBOMFound, reader.point.ScanFound = true, true, true
	report, err = service.Health(t.Context(), actor, "market_1")
	if err != nil || report.SupplyChainStatus != "verified" || !report.GeneratedAt.Equal(now) {
		t.Fatalf("complete references report=%#v error=%v", report, err)
	}
	reader.point.Collector.SignatureID = ""
	report, err = service.Health(t.Context(), actor, "market_1")
	if err != nil || report.SupplyChainStatus != "incomplete" {
		t.Fatalf("missing reference report=%#v error=%v", report, err)
	}
	if _, err := service.Health(t.Context(), actor, " "); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blank id error=%v", err)
	}
}
