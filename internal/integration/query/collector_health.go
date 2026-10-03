package query

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

var ErrNotFound = errors.New("integration resource not found")

// CollectorHealthPoint is a bounded, transaction-consistent view of a
// collector, its latest release, and its currently pinned release.
type CollectorHealthPoint struct {
	Collector     integrationdomain.Collector
	LatestRelease *integrationdomain.CollectorRelease
	PinnedRelease *integrationdomain.CollectorRelease
}

type CollectorHealthReader interface {
	GetCollectorHealthPoint(context.Context, string, string) (CollectorHealthPoint, error)
}

type CollectorHealth struct {
	reader CollectorHealthReader
	now    func() time.Time
}

func NewCollectorHealth(reader CollectorHealthReader, now func() time.Time) (*CollectorHealth, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &CollectorHealth{reader: reader, now: now}, nil
}

func (s *CollectorHealth) Report(ctx context.Context, actor identitydomain.Actor, id string) (integrationdomain.CollectorHealthReport, error) {
	var empty integrationdomain.CollectorHealthReport
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, scopeCollectorRead); err != nil {
		return empty, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, ErrNotFound
	}
	point, err := s.reader.GetCollectorHealthPoint(ctx, actor.TenantID, id)
	if err != nil {
		return empty, err
	}
	collector := point.Collector
	if collector.ID != id || collector.TenantID != actor.TenantID {
		return empty, ErrNotFound
	}
	if collector.APIKeyID == "" || collector.Status.IsZero() || collector.CreatedAt.IsZero() {
		return empty, ErrInvalidProjection
	}
	for _, release := range []*integrationdomain.CollectorRelease{point.LatestRelease, point.PinnedRelease} {
		if release != nil && (release.ID == "" || release.TenantID != actor.TenantID || release.CollectorID != id || release.CreatedAt.IsZero()) {
			return empty, ErrInvalidProjection
		}
	}
	if point.LatestRelease != nil && (point.LatestRelease.Version == "" || point.LatestRelease.HealthStatus == "") {
		return empty, ErrInvalidProjection
	}
	if point.PinnedRelease != nil && !point.PinnedRelease.Pinned {
		return empty, ErrInvalidProjection
	}
	checks := []integrationdomain.VerificationCheck{{Name: "collector_status", Result: "passed", Detail: collector.Status.String()}}
	supplyStatus := "missing_release_evidence"
	if point.LatestRelease == nil {
		checks = append(checks, integrationdomain.VerificationCheck{Name: "collector_release", Result: "failed"})
	} else {
		latest := point.LatestRelease
		checks = append(checks, integrationdomain.VerificationCheck{Name: "collector_release", Result: "passed", Detail: latest.Version})
		supplyStatus = latest.HealthStatus
		for _, evidence := range []struct{ name, id string }{
			{"collector_signature", latest.SignatureID}, {"collector_sbom", latest.SBOMID}, {"collector_scan", latest.ScanID},
		} {
			result := "passed"
			if evidence.id == "" {
				result = "failed"
			}
			checks = append(checks, integrationdomain.VerificationCheck{Name: evidence.name, Result: result})
		}
	}
	pinnedID := ""
	if point.PinnedRelease == nil {
		checks = append(checks, integrationdomain.VerificationCheck{Name: "collector_version_pinned", Result: "failed"})
	} else {
		pinnedID = point.PinnedRelease.ID
		checks = append(checks, integrationdomain.VerificationCheck{Name: "collector_version_pinned", Result: "passed", Detail: point.PinnedRelease.Version})
	}
	if point.LatestRelease != nil {
		copy := *point.LatestRelease
		copy.Limitations = append([]string(nil), copy.Limitations...)
		point.LatestRelease = &copy
	}
	return integrationdomain.CollectorHealthReport{
		ReportType: "collector_health", CollectorID: id, CollectorStatus: collector.Status.String(),
		Version: collector.Version, PinnedReleaseID: pinnedID, SupplyChainStatus: supplyStatus,
		Checks: checks, LatestRelease: point.LatestRelease,
		Assumptions: []string{"Collector health is based on metadata and evidence recorded in this tenant."},
		Limitations: []string{"This report does not prove collector runtime integrity or absence of vulnerabilities."},
		GeneratedAt: s.now(),
	}, nil
}
