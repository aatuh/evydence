package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ packagequery.ReleaseReadinessReportReader = (*Store)(nil)

// ReadReleaseReadinessReportSnapshot gathers only report-safe fields and
// canonical readiness facts in one read-only repeatable-read transaction.
func (s *Store) ReadReleaseReadinessReportSnapshot(ctx context.Context, tenantID, releaseID string, now time.Time) (packagequery.ReleaseReadinessReportSnapshot, error) {
	var empty packagequery.ReleaseReadinessReportSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(releaseID) == "" || now.IsZero() {
		return empty, packagequery.ErrReleaseReadinessValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin readiness report snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	facts, err := readReleaseReadinessSnapshotTx(ctx, tx, tenantID, releaseID, now)
	if errors.Is(err, riskapp.ErrNotFound) {
		return empty, packagequery.ErrReleaseReadinessNotFound
	}
	if errors.Is(err, riskapp.ErrValidation) {
		return empty, packagequery.ErrReleaseReadinessProjection
	}
	if err != nil {
		return empty, err
	}
	snapshot := packagequery.ReleaseReadinessReportSnapshot{Readiness: facts}
	remaining := packagequery.MaxReleaseReadinessEntries - len(facts.MissingCustomerStatementIDs) - len(facts.MissingNotAffectedReasonIDs) - len(facts.IncompleteExceptionIDs) - len(facts.InvalidPackageOrProfileIDs)
	if remaining < 0 {
		return empty, packagequery.ErrReleaseReadinessProjection
	}
	rows, err := tx.Query(ctx, releaseUnhandledFindingsCTE+` SELECT left(finding_id,1025),left(scan_id,1025),left(coalesce(vulnerability,''),1025),left(coalesce(component,''),1025),
		(octet_length(finding_id)>1024 OR octet_length(scan_id)>1024 OR octet_length(coalesce(vulnerability,''))>1024 OR octet_length(coalesce(component,''))>1024)
		FROM unhandled WHERE severity='critical' ORDER BY finding_id,scan_id LIMIT $4`, tenantID, releaseID, now, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read readiness report blockers: %w", err)
	}
	for rows.Next() {
		var finding packagedomain.BlockingFinding
		var oversized bool
		if err := rows.Scan(&finding.FindingID, &finding.ScanID, &finding.Vulnerability, &finding.Component, &oversized); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan readiness report blocker: %w", err)
		}
		if oversized || remaining == 0 {
			rows.Close()
			return empty, packagequery.ErrReleaseReadinessProjection
		}
		finding.ReleaseID, finding.Severity, finding.State = releaseID, "critical", "open"
		snapshot.BlockingFindings = append(snapshot.BlockingFindings, finding)
		remaining--
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return empty, fmt.Errorf("iterate readiness report blockers: %w", err)
	}
	rows.Close()
	// Explicit columns exclude decision notes, raw evidence, credentials, and
	// signing material. LEFT bounds allocation even for corrupted stored text;
	// the size flag rejects rather than silently truncating report evidence.
	rows, err = tx.Query(ctx, `SELECT left(id,1025),left(coalesce(finding_id,''),1025),left(coalesce(control_id,''),1025),left(reason,4097),left(owner,1025),expires_at,approved,
		left(coalesce(approved_by,''),1025),approved_at,created_at,
		(octet_length(id)>1024 OR octet_length(coalesce(finding_id,''))>1024 OR octet_length(coalesce(control_id,''))>1024 OR octet_length(reason)>4096 OR octet_length(owner)>1024 OR octet_length(coalesce(approved_by,''))>1024)
		FROM exceptions WHERE tenant_id=$1 AND release_id=$2 AND approved AND expires_at>$3 ORDER BY id LIMIT $4`, tenantID, releaseID, now, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read readiness report exceptions: %w", err)
	}
	for rows.Next() {
		var exception packagedomain.AcceptedExceptionSnapshot
		var oversized bool
		if err := rows.Scan(&exception.ID, &exception.FindingID, &exception.ControlID, &exception.Reason, &exception.Owner, &exception.ExpiresAt, &exception.Approved, &exception.ApprovedBy, &exception.ApprovedAt, &exception.CreatedAt, &oversized); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan readiness report exception: %w", err)
		}
		if oversized || remaining == 0 {
			rows.Close()
			return empty, packagequery.ErrReleaseReadinessProjection
		}
		exception.TenantID, exception.ReleaseID = tenantID, releaseID
		snapshot.AcceptedExceptions = append(snapshot.AcceptedExceptions, exception)
		remaining--
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return empty, fmt.Errorf("iterate readiness report exceptions: %w", err)
	}
	rows.Close()
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM vulnerability_decision_projection WHERE tenant_id=$1 AND release_id=$2 AND coalesce(superseded_by,'')=''),
		EXISTS(SELECT 1 FROM customer_security_packages WHERE tenant_id=$1 AND release_id=$2 AND state='generated' AND expires_at>$3)`, tenantID, releaseID, now).Scan(&snapshot.ActiveDecisionCount, &snapshot.HasActiveCustomerPackage)
	if err != nil {
		return empty, fmt.Errorf("read readiness report counts: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit readiness report snapshot: %w", err)
	}
	return snapshot, nil
}
