package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.MetricsReader = (*Store)(nil)

// ReadMetricsSnapshot returns tenant-filtered scalar aggregates. The optional
// global outbox aggregate is executed only after the caller requested explicit
// instance authority, and both reads share one repeatable-read snapshot.
func (s *Store) ReadMetricsSnapshot(ctx context.Context, tenantID string, includeOutbox bool) (operationsquery.MetricsSnapshot, error) {
	var empty operationsquery.MetricsSnapshot
	tenantID = strings.TrimSpace(tenantID)
	if s == nil || s.pool == nil || ctx == nil || tenantID == "" {
		return empty, operationsquery.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin metrics snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var audit, signatures, cosign, evidence, merkle, retention, bundles, transparency int64
	var portalFailures, portalRevoked int64
	var reconciliation operationsquery.ReconciliationCounts
	var lastRun *time.Time
	err = tx.QueryRow(ctx, `
		WITH portal AS (
			SELECT COALESCE(SUM(failed_access_count), 0) AS failures,
			       count(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked
			FROM customer_portal_access WHERE tenant_id = $1
		), reconciliation AS (
			SELECT count(*) AS runs,
			       COALESCE(SUM(scanned_payloads), 0) AS scanned,
			       COALESCE(SUM(missing_final_objects), 0) AS missing_final,
			       COALESCE(SUM(missing_staged_objects), 0) AS missing_staged,
			       COALESCE(SUM(digest_mismatches), 0) AS digest_mismatches,
			       COALESCE(SUM(provider_orphans), 0) AS provider_orphans,
			       COALESCE(SUM(quarantined_payloads), 0) AS quarantined,
			       MAX(created_at) AS last_run
			FROM object_reconciliation_receipts WHERE tenant_id = $1
		)
		SELECT (SELECT count(*) FROM audit_chain_entries WHERE tenant_id = $1),
		       (SELECT count(*) FROM artifact_signatures WHERE tenant_id = $1),
		       (SELECT count(*) FROM cosign_verifications WHERE tenant_id = $1),
		       (SELECT count(*) FROM evidence_items WHERE tenant_id = $1),
		       (SELECT count(*) FROM merkle_batches WHERE tenant_id = $1),
		       (SELECT count(*) FROM object_retention_policies WHERE tenant_id = $1),
		       (SELECT count(*) FROM release_bundles WHERE tenant_id = $1),
		       (SELECT count(*) FROM transparency_checkpoints WHERE tenant_id = $1),
		       portal.failures, portal.revoked,
		       reconciliation.runs, reconciliation.scanned,
		       reconciliation.missing_final, reconciliation.missing_staged,
		       reconciliation.digest_mismatches, reconciliation.provider_orphans,
		       reconciliation.quarantined, reconciliation.last_run
		FROM portal CROSS JOIN reconciliation
	`, tenantID).Scan(
		&audit, &signatures, &cosign, &evidence, &merkle, &retention, &bundles, &transparency,
		&portalFailures, &portalRevoked,
		&reconciliation.Runs, &reconciliation.ScannedPayloads,
		&reconciliation.MissingFinalObjects, &reconciliation.MissingStagedObjects,
		&reconciliation.DigestMismatches, &reconciliation.ProviderOrphans,
		&reconciliation.QuarantinedPayloads, &lastRun,
	)
	if err != nil {
		return empty, fmt.Errorf("read tenant metrics: %w", err)
	}
	maxInt := int64(^uint(0) >> 1)
	for _, count := range []int64{audit, signatures, cosign, evidence, merkle, retention, bundles, transparency, portalFailures, portalRevoked} {
		if count < 0 || count > maxInt {
			return empty, operationsquery.ErrInvalidProjection
		}
	}
	if lastRun != nil {
		reconciliation.LastRunAt = lastRun.UTC()
	}
	snapshot := operationsquery.MetricsSnapshot{
		ResourceCounts: map[string]int{
			"audit_chain_entries": int(audit), "artifact_signatures": int(signatures),
			"cosign_verifications": int(cosign), "evidence": int(evidence),
			"merkle_batches": int(merkle), "object_retention_policies": int(retention),
			"release_bundles": int(bundles), "transparency_checkpoints": int(transparency),
		},
		CustomerPortalFailedAccessCount:  int(portalFailures),
		CustomerPortalRevokedAccessCount: int(portalRevoked),
		Reconciliation:                   reconciliation,
	}
	if includeOutbox {
		var pending, running, terminal int64
		var oldest *time.Time
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status IN ('queued', 'retrying')),
			       count(*) FILTER (WHERE status = 'running'),
			       count(*) FILTER (WHERE status = 'dead_letter'),
			       min(created_at) FILTER (WHERE status IN ('queued', 'retrying'))
			FROM outbox_jobs
		`).Scan(&pending, &running, &terminal, &oldest); err != nil {
			return empty, fmt.Errorf("read global outbox metrics: %w", err)
		}
		if pending > maxInt || running > maxInt || terminal > maxInt {
			return empty, operationsquery.ErrInvalidProjection
		}
		snapshot.Outbox = &operationsquery.OutboxCounts{
			PendingJobs: int(pending), RunningJobs: int(running), TerminalJobs: int(terminal),
		}
		if oldest != nil {
			snapshot.Outbox.OldestPendingCreatedAt = oldest.UTC()
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit metrics snapshot: %w", err)
	}
	return snapshot, nil
}
