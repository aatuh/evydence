package app

// Historical characterization only. Runtime collector writes and health
// queries use the focused Integration services and current repositories.

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

type RecordCollectorReleaseInput struct {
	CollectorID    string
	Version        string
	ArtifactDigest string
	SignatureID    string
	SBOMID         string
	ScanID         string
	Pinned         bool
}

func (l *Ledger) RecordCollectorRelease(ctx context.Context, actor domain.Actor, in RecordCollectorReleaseInput) (domain.CollectorRelease, error) {
	if err := ctx.Err(); err != nil {
		return domain.CollectorRelease{}, err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.CollectorRelease{}, err
	}
	in.CollectorID = strings.TrimSpace(in.CollectorID)
	in.Version = strings.TrimSpace(in.Version)
	in.ArtifactDigest = strings.TrimSpace(in.ArtifactDigest)
	if in.CollectorID == "" || in.Version == "" || !validDigest(in.ArtifactDigest) {
		return domain.CollectorRelease{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	collector, ok := l.collectors[in.CollectorID]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.CollectorRelease{}, ErrNotFound
	}
	if in.SignatureID != "" {
		sig, ok := l.artifactSigs[strings.TrimSpace(in.SignatureID)]
		if !ok || sig.TenantID != actor.TenantID || sig.SubjectDigest != in.ArtifactDigest {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	if in.SBOMID != "" {
		sbom, ok := l.sboms[strings.TrimSpace(in.SBOMID)]
		if !ok || sbom.TenantID != actor.TenantID {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	if in.ScanID != "" {
		scan, ok := l.scans[strings.TrimSpace(in.ScanID)]
		if !ok || scan.TenantID != actor.TenantID {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	status := "recorded"
	health := "needs_evidence"
	if in.SignatureID != "" && in.SBOMID != "" && in.ScanID != "" {
		status = "evidence_complete"
		health = "healthy"
	}
	release := domain.CollectorRelease{
		ID:                 newID("colrel"),
		TenantID:           actor.TenantID,
		CollectorID:        collector.ID,
		Version:            in.Version,
		ArtifactDigest:     in.ArtifactDigest,
		SignatureID:        strings.TrimSpace(in.SignatureID),
		SBOMID:             strings.TrimSpace(in.SBOMID),
		ScanID:             strings.TrimSpace(in.ScanID),
		Pinned:             in.Pinned,
		VerificationStatus: status,
		HealthStatus:       health,
		Limitations:        []string{"Collector supply-chain status reflects evidence recorded in Evydence and does not prove collector runtime safety."},
		SchemaVersion:      domain.CollectorReleaseSchemaVersion,
		CreatedAt:          l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Builds.InsertCollectorRelease(ctx, release); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(release.CreatedAt, actor.TenantID, "collector_release.recorded", "collector", collector.ID, actorType(actor), actorID(actor), release.ArtifactDigest, ""))
			return err
		}); err != nil {
			return domain.CollectorRelease{}, err
		}
		if release.Pinned {
			for id, existing := range l.collectorReleases {
				if existing.TenantID == actor.TenantID && existing.CollectorID == collector.ID && existing.Pinned {
					existing.Pinned = false
					l.collectorReleases[id] = existing
				}
			}
		}
		l.collectorReleases[release.ID] = release
		l.publishCommittedAuditEntryLocked(entry)
		return release, nil
	}
	if in.Pinned {
		for id, existing := range l.collectorReleases {
			if existing.TenantID == actor.TenantID && existing.CollectorID == collector.ID && existing.Pinned {
				existing.Pinned = false
				l.collectorReleases[id] = existing
			}
		}
	}
	l.collectorReleases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "collector_release.recorded", "collector", collector.ID, actorType(actor), actorID(actor), release.ArtifactDigest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CollectorRelease{}, err
	}
	return release, nil
}

func (l *Ledger) CollectorHealthReport(ctx context.Context, actor domain.Actor, collectorID string) (domain.CollectorHealthReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeCollectorRead, resourceRefs{}); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	collector, ok := l.collectors[strings.TrimSpace(collectorID)]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.CollectorHealthReport{}, ErrNotFound
	}
	var latest *domain.CollectorRelease
	var pinned *domain.CollectorRelease
	for _, release := range l.collectorReleases {
		if release.TenantID != actor.TenantID || release.CollectorID != collector.ID {
			continue
		}
		copy := release
		if latest == nil || release.CreatedAt.After(latest.CreatedAt) {
			latest = &copy
		}
		if release.Pinned {
			pinned = &copy
		}
	}
	checks := []domain.VerifyCheck{{Name: "collector_status", Result: "passed", Detail: collector.Status}}
	supplyStatus := "missing_release_evidence"
	if latest == nil {
		checks = append(checks, domain.VerifyCheck{Name: "collector_release", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "collector_release", Result: "passed", Detail: latest.Version})
		supplyStatus = latest.HealthStatus
		if latest.SignatureID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_signature", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_signature", Result: "passed"})
		}
		if latest.SBOMID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_sbom", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_sbom", Result: "passed"})
		}
		if latest.ScanID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_scan", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_scan", Result: "passed"})
		}
	}
	pinnedID := ""
	if pinned != nil {
		pinnedID = pinned.ID
		checks = append(checks, domain.VerifyCheck{Name: "collector_version_pinned", Result: "passed", Detail: pinned.Version})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "collector_version_pinned", Result: "failed"})
	}
	return domain.CollectorHealthReport{
		ReportType:        "collector_health",
		CollectorID:       collector.ID,
		CollectorStatus:   collector.Status,
		Version:           collector.Version,
		PinnedReleaseID:   pinnedID,
		SupplyChainStatus: supplyStatus,
		Checks:            checks,
		LatestRelease:     latest,
		Assumptions:       []string{"Collector health is based on metadata and evidence recorded in this tenant."},
		Limitations:       []string{"This report does not prove collector runtime integrity or absence of vulnerabilities."},
		GeneratedAt:       l.now(),
	}, nil
}
