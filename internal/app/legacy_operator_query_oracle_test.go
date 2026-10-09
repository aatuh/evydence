package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// Unchanged historical algorithms remain package-local test oracles only.
func (l *Ledger) InstanceAdminSnapshot(ctx context.Context, actor domain.Actor) (domain.InstanceAdminSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return domain.InstanceAdminSnapshot{ReportType: "instance_admin_snapshot", TenantCount: len(l.tenants), ResourceCounts: map[string]int{"tenants": len(l.tenants), "users": len(l.users), "collectors": len(l.collectors), "evidence": len(l.evidence)}, Limitations: []string{"Instance admin diagnostics expose operational counts only and not raw evidence payloads or secrets."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) ReadinessStatus(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	checks := append([]ReadinessCheck(nil), l.readinessChecks...)
	l.mu.Unlock()
	return operationsquery.NewReadiness(checks).Public(ctx)
}

// ReadinessDiagnostics returns safe, dependency-specific diagnostics for an
// instance administrator. It deliberately excludes raw probe errors because
// those can contain credentials, hostnames, filesystem paths, or tenant data.
func (l *Ledger) ReadinessDiagnostics(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	checks := append([]ReadinessCheck(nil), l.readinessChecks...)
	l.mu.Unlock()
	return operationsquery.NewReadiness(checks).Operator(ctx, actor)
}

func (l *Ledger) Metrics(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	instanceAdmin := actorHasExactScope(actor, ScopeInstanceAdmin)
	if instanceAdmin {
		if err := require(actor, ScopeInstanceAdmin); err != nil {
			return nil, err
		}
	} else if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	portalFailures := 0
	portalRevoked := 0
	for _, access := range l.portalAccess {
		if access.TenantID == actor.TenantID {
			portalFailures += access.FailedAccessCount
			if access.RevokedAt != nil {
				portalRevoked++
			}
		}
	}
	metrics := map[string]any{"tenant_id": actor.TenantID, "resource_counts": l.resourceCountsLocked(actor.TenantID), "customer_portal_failed_access_count": portalFailures, "customer_portal_revoked_access_count": portalRevoked}
	operator := l.outboxAdmin
	reconciliationMetrics := l.reconciliationMetrics
	l.mu.Unlock()
	if reconciliationMetrics != nil {
		reconciliation, err := reconciliationMetrics.ObjectReconciliationMetrics(ctx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		metrics["object_reconciliation_runs"] = reconciliation.Runs
		metrics["object_reconciliation_scanned_payloads"] = reconciliation.ScannedPayloads
		metrics["object_reconciliation_missing_final_objects"] = reconciliation.MissingFinalObjects
		metrics["object_reconciliation_missing_staged_objects"] = reconciliation.MissingStagedObjects
		metrics["object_reconciliation_digest_mismatches"] = reconciliation.DigestMismatches
		metrics["object_reconciliation_provider_orphans"] = reconciliation.ProviderOrphans
		metrics["object_reconciliation_quarantined_payloads"] = reconciliation.QuarantinedPayloads
		lastRunAgeSeconds := 0
		if !reconciliation.LastRunAt.IsZero() {
			lastRunAgeSeconds = int(time.Since(reconciliation.LastRunAt).Seconds())
			if lastRunAgeSeconds < 0 {
				lastRunAgeSeconds = 0
			}
		}
		metrics["object_reconciliation_last_run_age_seconds"] = lastRunAgeSeconds
	}
	if !instanceAdmin || operator == nil {
		return metrics, nil
	}
	diagnostics, err := operator.OutboxDiagnostics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["outbox_pending_jobs"] = diagnostics.PendingJobs
	metrics["outbox_running_jobs"] = diagnostics.RunningJobs
	metrics["outbox_terminal_jobs"] = diagnostics.TerminalJobs
	oldestAgeSeconds := 0
	if !diagnostics.OldestPendingCreatedAt.IsZero() {
		oldestAgeSeconds = int(time.Since(diagnostics.OldestPendingCreatedAt).Seconds())
		if oldestAgeSeconds < 0 {
			oldestAgeSeconds = 0
		}
	}
	metrics["outbox_oldest_pending_age_seconds"] = oldestAgeSeconds
	return metrics, nil
}
