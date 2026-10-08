package httpapi

import "github.com/aatuh/evydence/internal/domain"

// Independent complete expected DTO for fixtures whose nonempty references
// were seeded in the same tenant. Missing and invalid reference behavior is
// separately checked against current repository points, not aggregate caches.
func expectedPeripheralFixtureHealth(v domain.MarketplaceCollector) domain.MarketplaceCollectorHealthReport {
	status := "verified"
	checks := []domain.VerifyCheck{{Name: "manifest_digest", Result: "passed", Detail: "collector package manifest digest is recorded"}}
	for _, ref := range []struct{ id, name, missing string }{
		{v.SignatureID, "signature_evidence", "collector package signature evidence is missing"},
		{v.SBOMID, "sbom_evidence", "collector package SBOM evidence is missing"},
		{v.ScanID, "vulnerability_scan_evidence", "collector package vulnerability scan evidence is missing"},
	} {
		check := domain.VerifyCheck{Name: ref.name, Result: "passed"}
		if ref.id == "" {
			status, check.Result, check.Detail = "incomplete", "failed", ref.missing
		}
		checks = append(checks, check)
	}
	return domain.MarketplaceCollectorHealthReport{ReportType: "marketplace_collector_health", CollectorID: v.ID, Name: v.Name, Provider: v.Provider, Version: v.Version, SupplyChainStatus: status, Checks: checks, Collector: v,
		Assumptions: []string{"Health is based on evidence recorded in Evydence for this tenant."}, Limitations: []string{"This report does not prove marketplace trust, package safety, or provider endorsement."}, GeneratedAt: peripheralFixtureQueryClock()}
}
