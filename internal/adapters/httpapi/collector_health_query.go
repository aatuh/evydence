package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func collectorHealthFromQuery(value integrationdomain.CollectorHealthReport) domain.CollectorHealthReport {
	checks := make([]domain.VerifyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, domain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	var latest *domain.CollectorRelease
	if value.LatestRelease != nil {
		release := value.LatestRelease
		latest = &domain.CollectorRelease{
			ID: release.ID, TenantID: release.TenantID, CollectorID: release.CollectorID,
			Version: release.Version, ArtifactDigest: release.ArtifactDigest,
			SignatureID: release.SignatureID, SBOMID: release.SBOMID, ScanID: release.ScanID,
			Pinned: release.Pinned, VerificationStatus: release.VerificationStatus,
			HealthStatus: release.HealthStatus, Limitations: release.Limitations,
			SchemaVersion: release.SchemaVersion, CreatedAt: release.CreatedAt,
		}
	}
	return domain.CollectorHealthReport{
		ReportType: value.ReportType, CollectorID: value.CollectorID,
		CollectorStatus: value.CollectorStatus, Version: value.Version,
		PinnedReleaseID: value.PinnedReleaseID, SupplyChainStatus: value.SupplyChainStatus,
		Checks: checks, LatestRelease: latest, Assumptions: value.Assumptions,
		Limitations: value.Limitations, GeneratedAt: value.GeneratedAt,
	}
}
