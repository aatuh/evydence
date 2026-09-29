// Package query owns bounded reads of explicitly experimental resources.
package query

import (
	"context"
	"errors"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var (
	ErrValidation        = errors.New("invalid marketplace collector query")
	ErrNotFound          = errors.New("marketplace collector not found")
	ErrInvalidProjection = errors.New("invalid marketplace collector projection")
)

type MarketplaceCollectorPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// MarketplaceCollectorPoint is a single database snapshot of a collector and
// whether each referenced evidence record currently belongs to its tenant.
// A missing ID and a dangling or foreign ID are distinct report states.
type MarketplaceCollectorPoint struct {
	Collector      experimentaldomain.MarketplaceCollector
	SignatureFound bool
	SBOMFound      bool
	ScanFound      bool
}

type MarketplaceCollectorReader interface {
	PageMarketplaceCollectors(context.Context, MarketplaceCollectorPageRequest) (appquery.Result[experimentaldomain.MarketplaceCollector], error)
	GetMarketplaceCollectorPoint(context.Context, string, string) (MarketplaceCollectorPoint, error)
}

type MarketplaceCollectors struct {
	reader MarketplaceCollectorReader
	now    func() time.Time
}

func NewMarketplaceCollectors(reader MarketplaceCollectorReader, now func() time.Time) (*MarketplaceCollectors, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &MarketplaceCollectors{reader: reader, now: now}, nil
}

func (s *MarketplaceCollectors) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	var empty appquery.Result[experimentaldomain.MarketplaceCollector]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "collector:read"); err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	result, err := s.reader.PageMarketplaceCollectors(ctx, MarketplaceCollectorPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort)) {
		return empty, ErrInvalidProjection
	}
	items := make([]experimentaldomain.MarketplaceCollector, 0, len(result.Items))
	for _, collector := range result.Items {
		if !validMarketplaceCollector(collector, actor.TenantID) {
			return empty, ErrInvalidProjection
		}
		collector.Limitations = append([]string(nil), collector.Limitations...)
		items = append(items, collector)
	}
	return appquery.Result[experimentaldomain.MarketplaceCollector]{Items: items, Next: result.Next}, nil
}

func (s *MarketplaceCollectors) Health(ctx context.Context, actor identitydomain.Actor, id string) (experimentaldomain.MarketplaceCollectorHealthReport, error) {
	var empty experimentaldomain.MarketplaceCollectorHealthReport
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "collector:read"); err != nil {
		return empty, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, ErrNotFound
	}
	point, err := s.reader.GetMarketplaceCollectorPoint(ctx, actor.TenantID, id)
	if err != nil {
		return empty, err
	}
	collector := point.Collector
	if collector.ID != id || collector.TenantID != actor.TenantID {
		return empty, ErrNotFound
	}
	if !validMarketplaceCollector(collector, actor.TenantID) {
		return empty, ErrInvalidProjection
	}
	collector.Limitations = append([]string(nil), collector.Limitations...)
	checks := []experimentaldomain.VerificationCheck{{Name: "manifest_digest", Result: "passed", Detail: "collector package manifest digest is recorded"}}
	status := "verified"
	for _, evidence := range []struct {
		id, name, missing, invalid string
		found                      bool
	}{
		{collector.SignatureID, "signature_evidence", "collector package signature evidence is missing", "collector package signature evidence reference is invalid", point.SignatureFound},
		{collector.SBOMID, "sbom_evidence", "collector package SBOM evidence is missing", "collector package SBOM evidence reference is invalid", point.SBOMFound},
		{collector.ScanID, "vulnerability_scan_evidence", "collector package vulnerability scan evidence is missing", "collector package vulnerability scan evidence reference is invalid", point.ScanFound},
	} {
		check := experimentaldomain.VerificationCheck{Name: evidence.name, Result: "passed"}
		if evidence.id == "" {
			if status == "verified" {
				status = "incomplete"
			}
			check.Result, check.Detail = "failed", evidence.missing
		} else if !evidence.found {
			status = "failed"
			check.Result, check.Detail = "failed", evidence.invalid
		}
		checks = append(checks, check)
	}
	return experimentaldomain.MarketplaceCollectorHealthReport{
		ReportType: "marketplace_collector_health", CollectorID: collector.ID,
		Name: collector.Name, Provider: collector.Provider, Version: collector.Version,
		SupplyChainStatus: status, Checks: checks, Collector: collector,
		Assumptions: []string{"Health is based on evidence recorded in Evydence for this tenant."},
		Limitations: []string{"This report does not prove marketplace trust, package safety, or provider endorsement."},
		GeneratedAt: s.now(),
	}, nil
}

func validMarketplaceCollector(collector experimentaldomain.MarketplaceCollector, tenantID string) bool {
	return collector.ID != "" && collector.TenantID == tenantID && collector.Name != "" && collector.Provider != "" && collector.Version != "" && collector.Publisher != "" && collector.ManifestHash != "" && collector.State != "" && collector.SchemaVersion != "" && !collector.CreatedAt.IsZero()
}
