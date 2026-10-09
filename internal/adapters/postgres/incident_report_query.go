package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.IncidentReportReader = (*Store)(nil)

// An incident package is one complete report, not a page. Refuse larger
// reports instead of truncating evidence or materializing unbounded rows.
const maxIncidentReportEntries = 4096

// ReadIncidentReport reads one verified incident and only its tenant-owned
// timeline and tasks from a repeatable-read database snapshot.
func (s *Store) ReadIncidentReport(ctx context.Context, tenantID, id string) (packagequery.IncidentReportSnapshot, error) {
	var empty packagequery.IncidentReportSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return empty, packagequery.ErrIncidentReportValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, packagequery.ErrIncidentReportNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin incident report snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	var snapshot packagequery.IncidentReportSnapshot
	var status string
	var releaseID sql.NullString
	var closedAt sql.NullTime
	err = tx.QueryRow(ctx, `
		SELECT i.id,i.tenant_id,i.product_id,i.release_id,i.title,i.severity,
		       i.status,i.opened_at,i.closed_at,i.schema_version,i.created_at
		FROM incidents AS i
		JOIN products AS p ON p.id=i.product_id AND p.tenant_id=i.tenant_id
		LEFT JOIN releases AS r ON r.id=i.release_id AND r.tenant_id=i.tenant_id AND r.product_id=i.product_id
		WHERE i.tenant_id=$1 AND i.id=$2 AND (i.release_id IS NULL OR r.id IS NOT NULL)
	`, tenantID, id).Scan(
		&snapshot.Incident.ID, &snapshot.Incident.TenantID, &snapshot.Incident.ProductID,
		&releaseID, &snapshot.Incident.Title, &snapshot.Incident.Severity,
		&status, &snapshot.Incident.OpenedAt, &closedAt,
		&snapshot.Incident.SchemaVersion, &snapshot.Incident.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, packagequery.ErrIncidentReportNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read incident report subject: %w", err)
	}
	snapshot.Incident.ReleaseID = nullableSQLString(releaseID)
	snapshot.Incident.ClosedAt = nullableSQLTime(closedAt)
	snapshot.Incident.Status, err = operationsdomain.ParseIncidentStatus(status)
	if err != nil {
		return empty, packagequery.ErrIncidentReportProjection
	}
	snapshot.Timeline = []operationsdomain.IncidentTimelineEvent{}
	snapshot.Tasks = []operationsdomain.RemediationTask{}
	events, err := tx.Query(ctx, `
		SELECT id,tenant_id,incident_id,event_type,summary,evidence_id,occurred_at,schema_version,created_at
		FROM incident_timeline_events
		WHERE tenant_id=$1 AND incident_id=$2
		ORDER BY occurred_at,id
		LIMIT $3`, tenantID, id, maxIncidentReportEntries+1)
	if err != nil {
		return empty, fmt.Errorf("read incident timeline: %w", err)
	}
	for events.Next() {
		var event operationsdomain.IncidentTimelineEvent
		var evidenceID sql.NullString
		if err := events.Scan(&event.ID, &event.TenantID, &event.IncidentID, &event.EventType, &event.Summary, &evidenceID, &event.OccurredAt, &event.SchemaVersion, &event.CreatedAt); err != nil {
			events.Close()
			return empty, fmt.Errorf("scan incident timeline event: %w", err)
		}
		event.EvidenceID = nullableSQLString(evidenceID)
		snapshot.Timeline = append(snapshot.Timeline, event)
	}
	err = events.Err()
	events.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate incident timeline: %w", err)
	}
	if len(snapshot.Timeline) > maxIncidentReportEntries {
		return empty, packagequery.ErrIncidentReportCapacity
	}
	tasks, err := tx.Query(ctx, `
		SELECT id,tenant_id,incident_id,release_id,title,owner,status,due_at,evidence_id,schema_version,created_at
		FROM remediation_tasks
		WHERE tenant_id=$1 AND incident_id=$2
		ORDER BY created_at,id
		LIMIT $3`, tenantID, id, maxIncidentReportEntries+1-len(snapshot.Timeline))
	if err != nil {
		return empty, fmt.Errorf("read incident tasks: %w", err)
	}
	for tasks.Next() {
		var task operationsdomain.RemediationTask
		var incidentID, releaseID, evidenceID sql.NullString
		var dueAt sql.NullTime
		if err := tasks.Scan(&task.ID, &task.TenantID, &incidentID, &releaseID, &task.Title, &task.Owner, &task.Status, &dueAt, &evidenceID, &task.SchemaVersion, &task.CreatedAt); err != nil {
			tasks.Close()
			return empty, fmt.Errorf("scan incident task: %w", err)
		}
		task.IncidentID = nullableSQLString(incidentID)
		task.ReleaseID = nullableSQLString(releaseID)
		task.DueAt = nullableSQLTime(dueAt)
		task.EvidenceID = nullableSQLString(evidenceID)
		snapshot.Tasks = append(snapshot.Tasks, task)
	}
	err = tasks.Err()
	tasks.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate incident tasks: %w", err)
	}
	if len(snapshot.Timeline)+len(snapshot.Tasks) > maxIncidentReportEntries {
		return empty, packagequery.ErrIncidentReportCapacity
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit incident report snapshot: %w", err)
	}
	return snapshot, nil
}
