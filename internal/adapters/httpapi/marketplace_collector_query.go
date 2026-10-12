package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
)

func marketplaceCollectorFromQuery(value experimentaldomain.MarketplaceCollector) domain.MarketplaceCollector {
	return domain.MarketplaceCollector{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Provider: value.Provider,
		Version: value.Version, Publisher: value.Publisher, ManifestHash: value.ManifestHash,
		SignatureID: value.SignatureID, SBOMID: value.SBOMID, ScanID: value.ScanID,
		State: value.State, Limitations: value.Limitations, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt,
	}
}

func marketplaceCollectorHealthFromQuery(value experimentaldomain.MarketplaceCollectorHealthReport) domain.MarketplaceCollectorHealthReport {
	checks := make([]domain.VerifyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, domain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return domain.MarketplaceCollectorHealthReport{
		ReportType: value.ReportType, CollectorID: value.CollectorID, Name: value.Name,
		Provider: value.Provider, Version: value.Version, SupplyChainStatus: value.SupplyChainStatus,
		Checks: checks, Collector: marketplaceCollectorFromQuery(value.Collector),
		Assumptions: value.Assumptions, Limitations: value.Limitations, GeneratedAt: value.GeneratedAt,
	}
}

func mapMarketplaceCollectorQueryError(err error) error {
	switch {
	case errors.Is(err, experimentalquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, experimentalquery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, experimentalquery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
