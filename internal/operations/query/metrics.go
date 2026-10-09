package query

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var metricResourceNames = []string{
	"audit_chain_entries", "artifact_signatures", "cosign_verifications",
	"evidence", "merkle_batches", "object_retention_policies",
	"release_bundles", "transparency_checkpoints",
}

// ReconciliationCounts contains tenant-safe receipt totals, never object keys.
type ReconciliationCounts struct {
	Runs                 int64
	ScannedPayloads      int64
	MissingFinalObjects  int64
	MissingStagedObjects int64
	DigestMismatches     int64
	ProviderOrphans      int64
	QuarantinedPayloads  int64
	LastRunAt            time.Time
}

// MetricsSnapshot is one database-consistent scalar projection. Outbox is
// present only when explicit instance-wide authority was requested.
type MetricsSnapshot struct {
	ResourceCounts                   map[string]int
	CustomerPortalFailedAccessCount  int
	CustomerPortalRevokedAccessCount int
	Reconciliation                   ReconciliationCounts
	Outbox                           *OutboxCounts
}

type MetricsReader interface {
	ReadMetricsSnapshot(context.Context, string, bool) (MetricsSnapshot, error)
}

type Metrics struct {
	reader MetricsReader
	now    func() time.Time
}

func NewMetrics(reader MetricsReader, now func() time.Time) (*Metrics, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &Metrics{reader: reader, now: now}, nil
}

// Snapshot authorizes before any read and preserves the existing JSON and
// Prometheus metric values without loading tenant state or raw payloads.
func (s *Metrics) Snapshot(ctx context.Context, actor identitydomain.Actor) (map[string]any, error) {
	if s == nil || ctx == nil {
		return nil, ErrValidation
	}
	instanceAdmin := actor.HasExplicitScope("instance:admin")
	if instanceAdmin {
		if err := application.AuthorizeInstanceScope(ctx, actor, "instance:admin"); err != nil {
			return nil, err
		}
	} else if err := application.AuthorizeTenantWideScope(ctx, actor, "admin"); err != nil {
		return nil, err
	}
	snapshot, err := s.reader.ReadMetricsSnapshot(ctx, actor.TenantID, instanceAdmin)
	if err != nil {
		return nil, err
	}
	if len(snapshot.ResourceCounts) != len(metricResourceNames) ||
		snapshot.CustomerPortalFailedAccessCount < 0 ||
		snapshot.CustomerPortalRevokedAccessCount < 0 ||
		!validReconciliationCounts(snapshot.Reconciliation) ||
		instanceAdmin != (snapshot.Outbox != nil) {
		return nil, ErrInvalidProjection
	}
	counts := make(map[string]int, len(metricResourceNames))
	for _, name := range metricResourceNames {
		count, ok := snapshot.ResourceCounts[name]
		if !ok || count < 0 {
			return nil, ErrInvalidProjection
		}
		counts[name] = count
	}
	reconciliation := snapshot.Reconciliation
	now := s.now().UTC()
	result := map[string]any{
		"tenant_id":                                    actor.TenantID,
		"resource_counts":                              counts,
		"customer_portal_failed_access_count":          snapshot.CustomerPortalFailedAccessCount,
		"customer_portal_revoked_access_count":         snapshot.CustomerPortalRevokedAccessCount,
		"object_reconciliation_runs":                   reconciliation.Runs,
		"object_reconciliation_scanned_payloads":       reconciliation.ScannedPayloads,
		"object_reconciliation_missing_final_objects":  reconciliation.MissingFinalObjects,
		"object_reconciliation_missing_staged_objects": reconciliation.MissingStagedObjects,
		"object_reconciliation_digest_mismatches":      reconciliation.DigestMismatches,
		"object_reconciliation_provider_orphans":       reconciliation.ProviderOrphans,
		"object_reconciliation_quarantined_payloads":   reconciliation.QuarantinedPayloads,
		"object_reconciliation_last_run_age_seconds":   metricAgeSeconds(now, reconciliation.LastRunAt),
	}
	if instanceAdmin {
		outbox := snapshot.Outbox
		if outbox.PendingJobs < 0 || outbox.RunningJobs < 0 || outbox.TerminalJobs < 0 ||
			(outbox.PendingJobs > 0 && outbox.OldestPendingCreatedAt.IsZero()) ||
			(outbox.PendingJobs == 0 && !outbox.OldestPendingCreatedAt.IsZero()) {
			return nil, ErrInvalidProjection
		}
		result["outbox_pending_jobs"] = outbox.PendingJobs
		result["outbox_running_jobs"] = outbox.RunningJobs
		result["outbox_terminal_jobs"] = outbox.TerminalJobs
		result["outbox_oldest_pending_age_seconds"] = metricAgeSeconds(now, outbox.OldestPendingCreatedAt)
	}
	return result, nil
}

func validReconciliationCounts(counts ReconciliationCounts) bool {
	return counts.Runs >= 0 && counts.ScannedPayloads >= 0 && counts.MissingFinalObjects >= 0 &&
		counts.MissingStagedObjects >= 0 && counts.DigestMismatches >= 0 &&
		counts.ProviderOrphans >= 0 && counts.QuarantinedPayloads >= 0 &&
		(counts.Runs == 0) == counts.LastRunAt.IsZero()
}

func metricAgeSeconds(now, then time.Time) int {
	if then.IsZero() || then.After(now) {
		return 0
	}
	return int(now.Sub(then).Seconds())
}
