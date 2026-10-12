package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// The unchanged historical security-update report is a test-only oracle.

func (l *Ledger) SecurityUpdateEvidenceReport(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.SecurityUpdateEvidenceReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityUpdateEvidenceReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.SecurityUpdateEvidenceReport{}, err
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if productID == "" || releaseID == "" {
		return domain.SecurityUpdateEvidenceReport{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.SecurityUpdateEvidenceReport{}, err
	}
	if err := l.ensureScopeLocked(actor.TenantID, productID, "", releaseID); err != nil {
		return domain.SecurityUpdateEvidenceReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: productID, ReleaseID: releaseID}); err != nil {
		return domain.SecurityUpdateEvidenceReport{}, err
	}
	evidenceIDs := []string{}
	for _, scan := range l.scans {
		if scan.TenantID == actor.TenantID && scan.ReleaseID == releaseID {
			evidenceIDs = append(evidenceIDs, scan.EvidenceID)
		}
	}
	fixedDecisions := []domain.VulnerabilityDecisionCustomerSummary{}
	for _, decision := range l.decisions {
		if decision.TenantID != actor.TenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" || decision.Status != decisionStatusFixed {
			continue
		}
		fixedDecisions = append(fixedDecisions, customerDecisionSummary(decision))
		evidenceIDs = append(evidenceIDs, decisionEvidenceIDs(decision.EvidenceID, decision.EvidenceIDs)...)
		if decision.VEXDocumentID != "" {
			if vex, ok := l.vexDocuments[decision.VEXDocumentID]; ok && vex.TenantID == actor.TenantID {
				evidenceIDs = append(evidenceIDs, vex.EvidenceID)
			}
		}
	}
	sort.Slice(fixedDecisions, func(i, j int) bool { return fixedDecisions[i].ID < fixedDecisions[j].ID })
	incidents := []domain.Incident{}
	for _, incident := range l.incidents {
		if incident.TenantID == actor.TenantID && incident.ProductID == productID && incident.ReleaseID == releaseID {
			incidents = append(incidents, incident)
		}
	}
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })
	tasks := []domain.RemediationTask{}
	for _, task := range l.tasks {
		if task.TenantID != actor.TenantID {
			continue
		}
		if task.ReleaseID == releaseID {
			tasks = append(tasks, task)
			evidenceIDs = append(evidenceIDs, task.EvidenceID)
			continue
		}
		if task.IncidentID != "" {
			if incident, ok := l.incidents[task.IncidentID]; ok && incident.TenantID == actor.TenantID && incident.ReleaseID == releaseID {
				tasks = append(tasks, task)
				evidenceIDs = append(evidenceIDs, task.EvidenceID)
			}
		}
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	evidenceIDs = sortedUniqueNonEmptyStrings(evidenceIDs)
	summary := map[string]int{
		"fixed_decisions_total":    len(fixedDecisions),
		"incidents_total":          len(incidents),
		"remediation_tasks_total":  len(tasks),
		"linked_evidence_total":    len(evidenceIDs),
		"security_update_subjects": len(fixedDecisions) + len(incidents) + len(tasks),
	}
	return domain.SecurityUpdateEvidenceReport{
		ReportType:       "security_update_evidence",
		TemplateVersion:  "security-update-evidence.v1.0.0",
		ProductID:        productID,
		ReleaseID:        releaseID,
		Summary:          summary,
		FixedDecisions:   fixedDecisions,
		Incidents:        incidents,
		RemediationTasks: tasks,
		EvidenceIDs:      evidenceIDs,
		Assumptions:      []string{"This report summarizes recorded release evidence that may support security update review."},
		Limitations:      []string{"Security update evidence is scoped to records in this Evydence tenant and does not prove legal sufficiency, customer notification completeness, or release security status."},
		GeneratedAt:      l.now(),
	}, nil
}
