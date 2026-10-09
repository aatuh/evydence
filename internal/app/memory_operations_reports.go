package app

import (
	"context"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.IncidentReportReader = memoryRiskRepository{}
var _ operationsquery.RetentionReader = memoryGovernanceRepository{}

// Mirror the native report's combined entry ceiling in the typed test model.
// This does not establish SQL transfer, byte budgets, locks or durability.
const memoryIncidentReportEntries = 4096

func (r memoryRiskRepository) ReadIncidentReport(ctx context.Context, tenant, id string) (packagequery.IncidentReportSnapshot, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return packagequery.IncidentReportSnapshot{}, packagequery.ErrIncidentReportNotFound
	}
	var out packagequery.IncidentReportSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		incident, ok := s.Incidents[id]
		if !ok || incident.ID != id || incident.TenantID != tenant || incident.ProductID == "" {
			return packagequery.ErrIncidentReportNotFound
		}
		if _, err := memoryGovernanceProductRelease(s, tenant, incident.ProductID, incident.ReleaseID); err != nil {
			return packagequery.ErrIncidentReportNotFound
		}
		value, err := domain.IncidentToContextModel(incident)
		if err != nil {
			return packagequery.ErrIncidentReportProjection
		}
		out = packagequery.IncidentReportSnapshot{Incident: value, Timeline: []operationsdomain.IncidentTimelineEvent{}, Tasks: []operationsdomain.RemediationTask{}}
		for key, event := range s.IncidentTimelineEvents {
			if err := ctx.Err(); err != nil {
				return err
			}
			if event.TenantID != tenant || event.IncidentID != id {
				continue
			}
			if event.ID == "" || event.ID != key {
				return packagequery.ErrIncidentReportProjection
			}
			if len(out.Timeline) == memoryIncidentReportEntries {
				return packagequery.ErrIncidentReportCapacity
			}
			out.Timeline = append(out.Timeline, operationsdomain.IncidentTimelineEvent(event))
		}
		for key, task := range s.RemediationTasks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if task.TenantID != tenant || task.IncidentID != id {
				continue
			}
			if task.ID == "" || task.ID != key {
				return packagequery.ErrIncidentReportProjection
			}
			if len(out.Timeline)+len(out.Tasks) == memoryIncidentReportEntries {
				return packagequery.ErrIncidentReportCapacity
			}
			value := operationsdomain.RemediationTask(task)
			value.DueAt = cloneTimePtr(task.DueAt)
			out.Tasks = append(out.Tasks, value)
		}
		slices.SortFunc(out.Timeline, func(a, b operationsdomain.IncidentTimelineEvent) int {
			if c := a.OccurredAt.Compare(b.OccurredAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		slices.SortFunc(out.Tasks, func(a, b operationsdomain.RemediationTask) int {
			if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		return ctx.Err()
	})
	if err != nil {
		return packagequery.IncidentReportSnapshot{}, err
	}
	return out, nil
}

// Retention mirrors native inventory/filter/order semantics. Native retention
// currently has no row/byte ceiling; this model must not imply that it does.
func (r memoryGovernanceRepository) ReadRetentionRecords(ctx context.Context, tenant, kind, id string) (operationsquery.RetentionSnapshot, error) {
	var out operationsquery.RetentionSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		out = operationsquery.RetentionSnapshot{LegalHolds: []operationsdomain.LegalHold{}, RetentionOverrides: []operationsdomain.RetentionOverride{}}
		for key, hold := range s.LegalHolds {
			if err := ctx.Err(); err != nil {
				return err
			}
			if hold.TenantID != tenant || kind != "" && (hold.ScopeType != kind || hold.ScopeID != id) {
				continue
			}
			if hold.ID == "" || hold.ID != key {
				return operationsquery.ErrInvalidProjection
			}
			v := operationsdomain.LegalHold(hold)
			v.ReleasedAt = cloneTimePtr(hold.ReleasedAt)
			out.LegalHolds = append(out.LegalHolds, v)
		}
		for key, v := range s.RetentionOverrides {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || kind != "" && (v.ScopeType != kind || v.ScopeID != id) {
				continue
			}
			if v.ID == "" || v.ID != key {
				return operationsquery.ErrInvalidProjection
			}
			out.RetentionOverrides = append(out.RetentionOverrides, operationsdomain.RetentionOverride(v))
		}
		slices.SortFunc(out.LegalHolds, func(a, b operationsdomain.LegalHold) int {
			if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		slices.SortFunc(out.RetentionOverrides, func(a, b operationsdomain.RetentionOverride) int {
			if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		return ctx.Err()
	})
	if err != nil {
		return operationsquery.RetentionSnapshot{}, err
	}
	return out, nil
}
