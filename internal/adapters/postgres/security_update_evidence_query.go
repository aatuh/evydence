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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ packagequery.SecurityUpdateReader = (*Store)(nil)

// ReadSecurityUpdateSnapshot reads one release's report-safe facts from a
// repeatable-read view. Every table is tenant/release filtered and each
// record-set is limited by the remaining complete-report row budget.
func (s *Store) ReadSecurityUpdateSnapshot(ctx context.Context, tenantID, productID, releaseID string) (packagequery.SecurityUpdateSnapshot, error) {
	var empty packagequery.SecurityUpdateSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(productID) == "" || strings.TrimSpace(releaseID) == "" {
		return empty, packagequery.ErrSecurityUpdateValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin security update snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	snapshot := packagequery.SecurityUpdateSnapshot{
		ScanEvidenceIDs: []string{}, VEXEvidenceIDs: map[string]string{},
		Decisions: []riskdomain.VulnerabilityDecision{}, Incidents: []operationsdomain.Incident{},
		Tasks: []operationsdomain.RemediationTask{},
	}
	err = tx.QueryRow(ctx, `
		SELECT r.tenant_id,p.id,r.id FROM releases AS r
		JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND p.id=$2 AND r.id=$3`, tenantID, productID, releaseID).Scan(&snapshot.TenantID, &snapshot.ProductID, &snapshot.ReleaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, packagequery.ErrSecurityUpdateNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("resolve security update release: %w", err)
	}
	remaining := packagequery.MaxSecurityUpdateEntries
	scans, err := tx.Query(ctx, `
		SELECT s.evidence_id,e.id FROM vulnerability_scans AS s
		LEFT JOIN evidence_items AS e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id
		WHERE s.tenant_id=$1 AND s.release_id=$2
		ORDER BY s.created_at,s.id LIMIT $3`, tenantID, releaseID, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read security update scans: %w", err)
	}
	for scans.Next() {
		var evidenceID string
		var verifiedID sql.NullString
		if err := scans.Scan(&evidenceID, &verifiedID); err != nil {
			scans.Close()
			return empty, fmt.Errorf("scan security update evidence: %w", err)
		}
		if !verifiedID.Valid {
			scans.Close()
			return empty, packagequery.ErrSecurityUpdateProjection
		}
		snapshot.ScanEvidenceIDs = append(snapshot.ScanEvidenceIDs, evidenceID)
	}
	err = scans.Err()
	scans.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate security update scans: %w", err)
	}
	if len(snapshot.ScanEvidenceIDs) > remaining {
		return empty, packagequery.ErrSecurityUpdateCapacity
	}
	remaining -= len(snapshot.ScanEvidenceIDs)
	decisions, err := tx.Query(ctx, `
		SELECT d.id,d.tenant_id,d.finding_id,d.scan_id,d.release_id,p.id,
		       d.vulnerability,d.component,d.sbom_id,d.sbom_component_purl,d.sbom_component_name,
		       d.status,d.justification,d.impact_statement,d.action_statement,
		       d.customer_visible,d.source,d.evidence_id,d.evidence_ids,d.supporting_refs,
		       d.vex_document_id,d.supersedes,d.superseded_by,d.approved_by,
		       d.reviewed_at,d.review_due_at,d.schema_version,d.created_at
		FROM vulnerability_decision_projection AS d
		JOIN releases AS r ON r.id=d.release_id AND r.tenant_id=d.tenant_id
		JOIN products AS p ON p.id=r.product_id AND p.tenant_id=d.tenant_id
		WHERE d.tenant_id=$1 AND d.release_id=$2 AND p.id=$3
		  AND d.status='fixed' AND d.superseded_by IS NULL
		ORDER BY d.id LIMIT $4`, tenantID, releaseID, productID, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read security update decisions: %w", err)
	}
	for decisions.Next() {
		point, err := scanVulnerabilityDecisionPoint(decisions)
		if err != nil {
			decisions.Close()
			if errors.Is(err, riskquery.ErrInvalidProjection) {
				return empty, packagequery.ErrSecurityUpdateProjection
			}
			return empty, err
		}
		snapshot.Decisions = append(snapshot.Decisions, point.Decision)
	}
	err = decisions.Err()
	decisions.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate security update decisions: %w", err)
	}
	if len(snapshot.Decisions) > remaining {
		return empty, packagequery.ErrSecurityUpdateCapacity
	}
	remaining -= len(snapshot.Decisions)
	vexIDs := make([]string, 0, len(snapshot.Decisions))
	for _, decision := range snapshot.Decisions {
		if decision.VEXDocumentID != "" {
			vexIDs = append(vexIDs, decision.VEXDocumentID)
		}
	}
	if len(vexIDs) > 0 {
		vex, err := tx.Query(ctx, `
			SELECT v.id,v.evidence_id,e.id FROM vex_documents AS v
			LEFT JOIN evidence_items AS e ON e.id=v.evidence_id AND e.tenant_id=v.tenant_id
			WHERE v.tenant_id=$1 AND v.release_id=$2 AND v.id=ANY($3::text[])
			ORDER BY v.id LIMIT $4`, tenantID, releaseID, vexIDs, len(vexIDs))
		if err != nil {
			return empty, fmt.Errorf("read security update VEX evidence: %w", err)
		}
		for vex.Next() {
			var id, evidenceID string
			var verifiedID sql.NullString
			if err := vex.Scan(&id, &evidenceID, &verifiedID); err != nil {
				vex.Close()
				return empty, fmt.Errorf("scan security update VEX evidence: %w", err)
			}
			if !verifiedID.Valid {
				vex.Close()
				return empty, packagequery.ErrSecurityUpdateProjection
			}
			snapshot.VEXEvidenceIDs[id] = evidenceID
		}
		err = vex.Err()
		vex.Close()
		if err != nil {
			return empty, fmt.Errorf("iterate security update VEX evidence: %w", err)
		}
	}
	incidents, err := tx.Query(ctx, `
		SELECT i.id,i.tenant_id,i.product_id,i.release_id,i.title,i.severity,
		       i.status,i.opened_at,i.closed_at,i.schema_version,i.created_at
		FROM incidents AS i
		WHERE i.tenant_id=$1 AND i.product_id=$2 AND i.release_id=$3
		ORDER BY i.id LIMIT $4`, tenantID, productID, releaseID, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read security update incidents: %w", err)
	}
	for incidents.Next() {
		var incident operationsdomain.Incident
		var status string
		var closedAt sql.NullTime
		if err := incidents.Scan(&incident.ID, &incident.TenantID, &incident.ProductID, &incident.ReleaseID,
			&incident.Title, &incident.Severity, &status, &incident.OpenedAt, &closedAt,
			&incident.SchemaVersion, &incident.CreatedAt); err != nil {
			incidents.Close()
			return empty, fmt.Errorf("scan security update incident: %w", err)
		}
		incident.Status, err = operationsdomain.ParseIncidentStatus(status)
		if err != nil {
			incidents.Close()
			return empty, packagequery.ErrSecurityUpdateProjection
		}
		incident.ClosedAt = nullableSQLTime(closedAt)
		snapshot.Incidents = append(snapshot.Incidents, incident)
	}
	err = incidents.Err()
	incidents.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate security update incidents: %w", err)
	}
	if len(snapshot.Incidents) > remaining {
		return empty, packagequery.ErrSecurityUpdateCapacity
	}
	remaining -= len(snapshot.Incidents)
	tasks, err := tx.Query(ctx, `
		SELECT t.id,t.tenant_id,t.incident_id,t.release_id,t.title,t.owner,
		       t.status,t.due_at,t.evidence_id,t.schema_version,t.created_at
		FROM remediation_tasks AS t
		LEFT JOIN incidents AS i ON i.id=t.incident_id AND i.tenant_id=t.tenant_id
		  AND i.product_id=$2 AND i.release_id=$3
		WHERE t.tenant_id=$1 AND (t.release_id IS NULL OR t.release_id=$3)
		  AND (t.incident_id IS NULL OR i.id IS NOT NULL)
		  AND (t.release_id=$3 OR i.id IS NOT NULL)
		ORDER BY t.id LIMIT $4`, tenantID, productID, releaseID, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read security update tasks: %w", err)
	}
	for tasks.Next() {
		var task operationsdomain.RemediationTask
		var incidentID, taskReleaseID, evidenceID sql.NullString
		var dueAt sql.NullTime
		if err := tasks.Scan(&task.ID, &task.TenantID, &incidentID, &taskReleaseID,
			&task.Title, &task.Owner, &task.Status, &dueAt, &evidenceID,
			&task.SchemaVersion, &task.CreatedAt); err != nil {
			tasks.Close()
			return empty, fmt.Errorf("scan security update task: %w", err)
		}
		task.IncidentID, task.ReleaseID = nullableSQLString(incidentID), nullableSQLString(taskReleaseID)
		task.DueAt, task.EvidenceID = nullableSQLTime(dueAt), nullableSQLString(evidenceID)
		snapshot.Tasks = append(snapshot.Tasks, task)
	}
	err = tasks.Err()
	tasks.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate security update tasks: %w", err)
	}
	if len(snapshot.Tasks) > remaining {
		return empty, packagequery.ErrSecurityUpdateCapacity
	}
	if err := verifySecurityUpdateEvidenceRefs(ctx, tx, snapshot); err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit security update snapshot: %w", err)
	}
	return snapshot, nil
}

func verifySecurityUpdateEvidenceRefs(ctx context.Context, tx pgx.Tx, snapshot packagequery.SecurityUpdateSnapshot) error {
	ids := make(map[string]struct{})
	add := func(id string) error {
		id = strings.TrimSpace(id)
		if id != "" {
			ids[id] = struct{}{}
		}
		if len(ids) > packagequery.MaxSecurityUpdateEntries {
			return packagequery.ErrSecurityUpdateCapacity
		}
		return nil
	}
	for _, id := range snapshot.ScanEvidenceIDs {
		if err := add(id); err != nil {
			return err
		}
	}
	for _, decision := range snapshot.Decisions {
		if err := add(decision.EvidenceID); err != nil {
			return err
		}
		for _, id := range decision.EvidenceIDs {
			if err := add(id); err != nil {
				return err
			}
		}
		for _, ref := range decision.SupportingRefs {
			if ref.Type == "evidence" {
				if err := add(ref.ID); err != nil {
					return err
				}
			}
		}
	}
	for _, id := range snapshot.VEXEvidenceIDs {
		if err := add(id); err != nil {
			return err
		}
	}
	for _, task := range snapshot.Tasks {
		if err := add(task.EvidenceID); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return nil
	}
	wanted := make([]string, 0, len(ids))
	for id := range ids {
		wanted = append(wanted, id)
	}
	valid, err := verifyScopedReportEvidence(ctx, tx, snapshot.TenantID, snapshot.ProductID, snapshot.ReleaseID, wanted)
	if err != nil {
		return err
	}
	if !valid {
		return packagequery.ErrSecurityUpdateProjection
	}
	return nil
}
