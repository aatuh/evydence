package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical report implementations, excluded from production builds.
func (l *Ledger) IncidentReport(ctx context.Context, actor domain.Actor, incidentID string) (domain.IncidentReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentReport{}, err
	}
	if err := require(actor, ScopeIncidentRead); err != nil {
		return domain.IncidentReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	incident, ok := l.incidents[strings.TrimSpace(incidentID)]
	if !ok || incident.TenantID != actor.TenantID {
		return domain.IncidentReport{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentRead, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
		return domain.IncidentReport{}, err
	}
	timeline := []domain.IncidentTimelineEvent{}
	linked := []string{}
	for _, event := range l.timeline {
		if event.TenantID == actor.TenantID && event.IncidentID == incident.ID {
			timeline = append(timeline, event)
			if event.EvidenceID != "" {
				linked = append(linked, event.EvidenceID)
			}
		}
	}
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].OccurredAt.Before(timeline[j].OccurredAt) })
	tasks := []domain.RemediationTask{}
	for _, task := range l.tasks {
		if task.TenantID == actor.TenantID && task.IncidentID == incident.ID {
			tasks = append(tasks, task)
			if task.EvidenceID != "" {
				linked = append(linked, task.EvidenceID)
			}
		}
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.Before(tasks[j].CreatedAt) })
	result := "open"
	if incident.Status == "closed" {
		result = "closed"
	}
	return domain.IncidentReport{
		ReportType:      "incident_package",
		TemplateVersion: "incident-package.v1.0.0",
		IncidentID:      incident.ID,
		Result:          result,
		Timeline:        timeline,
		Tasks:           tasks,
		LinkedEvidence:  sortedStrings(linked),
		Assumptions:     []string{"Incident evidence is limited to records stored in this Evydence tenant."},
		Limitations:     []string{"This report organizes incident evidence and does not prove root cause completeness or remediation sufficiency."},
		GeneratedAt:     l.now(),
	}, nil
}

func (l *Ledger) RetentionReport(ctx context.Context, actor domain.Actor, scopeType, scopeID string) (domain.RetentionReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.RetentionReport{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	holds := []domain.LegalHold{}
	for _, hold := range l.legalHolds {
		if hold.TenantID == actor.TenantID && (scopeType == "" || (hold.ScopeType == scopeType && hold.ScopeID == scopeID)) {
			holds = append(holds, hold)
		}
	}
	overrides := []domain.RetentionOverride{}
	for _, override := range l.retentionOverrides {
		if override.TenantID == actor.TenantID && (scopeType == "" || (override.ScopeType == scopeType && override.ScopeID == scopeID)) {
			overrides = append(overrides, override)
		}
	}
	return domain.RetentionReport{ReportType: "retention", ScopeType: scopeType, ScopeID: scopeID, LegalHolds: holds, RetentionOverrides: overrides, Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."}, GeneratedAt: l.now()}, nil
}
