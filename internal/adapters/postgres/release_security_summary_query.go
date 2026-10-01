package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ReleaseSecuritySummaryReader = (*Store)(nil)

// ReadReleaseSecuritySummarySnapshot resolves readiness, workflow counts, and
// report-safe risk metadata from one committed tenant-scoped view.
func (s *Store) ReadReleaseSecuritySummarySnapshot(ctx context.Context, tenantID, releaseID string) (riskquery.ReleaseSecuritySummarySnapshot, error) {
	var empty riskquery.ReleaseSecuritySummarySnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(releaseID) == "" {
		return empty, riskquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin release security summary: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	now := time.Now().UTC()
	readiness, err := readReleaseReadinessSnapshotTx(ctx, tx, tenantID, releaseID, now)
	if errors.Is(err, riskapp.ErrNotFound) {
		return empty, riskquery.ErrNotFound
	}
	if errors.Is(err, riskapp.ErrValidation) {
		return empty, riskquery.ErrInvalidProjection
	}
	if err != nil {
		return empty, err
	}
	snapshot := riskquery.ReleaseSecuritySummarySnapshot{TenantID: tenantID, Readiness: readiness}
	var oversizedSummaryValue bool
	err = tx.QueryRow(ctx, `SELECT p.id,left(p.name,1025),left(p.slug,1025),r.id,left(r.version,1025),left(r.state,1025),
		octet_length(p.name)>1024 OR octet_length(p.slug)>1024 OR octet_length(r.version)>1024 OR octet_length(r.state)>1024
		FROM releases AS r JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND r.id=$2`, tenantID, releaseID).Scan(
		&snapshot.Product.ID, &snapshot.Product.Name, &snapshot.Product.Slug,
		&snapshot.Release.ID, &snapshot.Release.Version, &snapshot.Release.State, &oversizedSummaryValue,
	)
	if err != nil {
		return empty, fmt.Errorf("read release security scope: %w", err)
	}
	if oversizedSummaryValue || snapshot.Product.ID != readiness.ProductID {
		return empty, riskquery.ErrInvalidProjection
	}
	flow, err := readEvidenceFlowSnapshot(ctx, tx, tenantID, releaseID)
	if err != nil {
		return empty, err
	}
	if flow.ProductID != readiness.ProductID || flow.ReleaseID != releaseID || flow.TenantID != tenantID {
		return empty, riskquery.ErrInvalidProjection
	}
	snapshot.Counts = flow.Counts
	snapshot.OpenFindingsBySeverity, err = readSecuritySummaryGroups(ctx, tx, `SELECT left(lower(coalesce(nullif(f.value->>'severity',''),'unknown')),65),count(*)
		FROM vulnerability_scans AS s
		CROSS JOIN LATERAL jsonb_array_elements(s.findings) AS f(value)
		WHERE s.tenant_id=$1 AND s.release_id=$2 AND lower(coalesce(nullif(f.value->>'state',''),'open'))='open'
		GROUP BY lower(coalesce(nullif(f.value->>'severity',''),'unknown'))
		ORDER BY 1 LIMIT 33`, tenantID, releaseID)
	if err != nil {
		return empty, err
	}
	snapshot.DecisionsByStatus, err = readSecuritySummaryGroups(ctx, tx, `SELECT left(status,65),count(*) FROM vulnerability_decisions
		WHERE tenant_id=$1 AND release_id=$2 AND coalesce(superseded_by,'')=''
		GROUP BY status ORDER BY 1 LIMIT 33`, tenantID, releaseID)
	if err != nil {
		return empty, err
	}
	rows, err := tx.Query(ctx, releaseUnhandledFindingsCTE+` SELECT left(finding_id,1025),left(scan_id,1025),left(coalesce(vulnerability,''),1025),left(coalesce(component,''),1025),left(severity,65),left(state,65),
		(octet_length(finding_id)>1024 OR octet_length(scan_id)>1024 OR octet_length(coalesce(vulnerability,''))>1024 OR octet_length(coalesce(component,''))>1024 OR octet_length(severity)>64 OR octet_length(state)>64)
		FROM unhandled ORDER BY finding_id,scan_id LIMIT $4`, tenantID, releaseID, now, riskquery.MaxSecuritySummaryFindings+1)
	if err != nil {
		return empty, fmt.Errorf("read release security missing decisions: %w", err)
	}
	for rows.Next() {
		if len(snapshot.MissingRequiredDecisions) >= riskquery.MaxSecuritySummaryFindings {
			rows.Close()
			return empty, riskquery.ErrInvalidProjection
		}
		var item riskdomain.ReleaseSecurityMissingDecision
		var oversized bool
		if err := rows.Scan(&item.FindingID, &item.ScanID, &item.Vulnerability, &item.Component, &item.Severity, &item.State, &oversized); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan release security finding: %w", err)
		}
		if oversized {
			rows.Close()
			return empty, riskquery.ErrInvalidProjection
		}
		snapshot.MissingRequiredDecisions = append(snapshot.MissingRequiredDecisions, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return empty, fmt.Errorf("iterate release security findings: %w", err)
	}
	rows.Close()
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM approval_records WHERE tenant_id=$1 AND subject_type='release' AND subject_id=$2),
		(SELECT count(*) FROM approval_records WHERE tenant_id=$1 AND subject_type='release' AND subject_id=$2 AND decision='approved'),
		(SELECT count(*) FROM exceptions WHERE tenant_id=$1 AND release_id=$2),
		(SELECT count(*) FROM exceptions WHERE tenant_id=$1 AND release_id=$2 AND expires_at>$3 AND approved),
		(SELECT count(*) FROM exceptions WHERE tenant_id=$1 AND release_id=$2 AND expires_at>$3 AND NOT approved),
		(SELECT count(*) FROM exceptions WHERE tenant_id=$1 AND release_id=$2 AND expires_at<=$3)`, tenantID, releaseID, now).Scan(
		&snapshot.ApprovalSummary.Total, &snapshot.ApprovalSummary.Approved,
		&snapshot.ExceptionSummary.Total, &snapshot.ExceptionSummary.ApprovedUnexpired, &snapshot.ExceptionSummary.Unapproved, &snapshot.ExceptionSummary.Expired,
	)
	if err != nil {
		return empty, fmt.Errorf("read release security governance counts: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit release security summary: %w", err)
	}
	return snapshot, nil
}

func readSecuritySummaryGroups(ctx context.Context, tx pgx.Tx, query, tenantID, releaseID string) (map[string]int, error) {
	rows, err := tx.Query(ctx, query, tenantID, releaseID)
	if err != nil {
		return nil, fmt.Errorf("read release security groups: %w", err)
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		if len(result) >= 32 {
			return nil, riskquery.ErrInvalidProjection
		}
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, fmt.Errorf("scan release security group: %w", err)
		}
		if key == "" || len(key) > 64 || count < 0 {
			return nil, riskquery.ErrInvalidProjection
		}
		result[key] = int(count)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate release security groups: %w", err)
	}
	return result, nil
}
