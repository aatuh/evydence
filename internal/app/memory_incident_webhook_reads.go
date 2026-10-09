package app

import (
	"context"
	"strings"

	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

var _ operationsapp.IncidentWebhookRouting = memoryRiskRepository{}
var _ operationsapp.IncidentWebhookReader = memoryRiskRepository{}

// Routing exposes only a bounded tenant locator. Receiver/replay reads use the
// already locked typed snapshot, not native database fences or durability.
func (r memoryRiskRepository) LookupIncidentWebhookTenant(ctx context.Context, id string) (string, error) {
	if ctx == nil || r.uow == nil || id == "" || strings.TrimSpace(id) != id || !memoryGovernanceText(id, 1024) {
		return "", ErrValidation
	}
	var tenant string
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.IncidentWebhookReceivers[id]
		if !ok || v.ID != id {
			return ErrNotFound
		}
		if v.TenantID == "" || strings.TrimSpace(v.TenantID) != v.TenantID || !memoryGovernanceText(v.TenantID, 1024) {
			return ErrValidation
		}
		tenant = v.TenantID
		return nil
	})
	if err != nil {
		return "", err
	}
	return tenant, nil
}
func (r memoryRiskRepository) ReadIncidentWebhookReceiver(ctx context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	var out operationsdomain.IncidentWebhookReceiver
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.IncidentWebhookReceivers[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		for _, field := range []struct {
			value string
			limit int
		}{{v.IncidentID, 1024}, {v.Provider, 65536}, {v.PublicKey, 1024}, {v.Status, 128}} {
			if !memoryGovernanceText(field.value, field.limit) {
				return ErrValidation
			}
		}
		out = operationsdomain.IncidentWebhookReceiver{ID: id, TenantID: tenant, IncidentID: v.IncidentID, Provider: v.Provider, PublicKey: v.PublicKey, Status: v.Status}
		return nil
	})
	if err != nil {
		return operationsdomain.IncidentWebhookReceiver{}, err
	}
	return out, nil
}
func (r memoryRiskRepository) ReadIncidentWebhookReplay(ctx context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	var out operationsdomain.IncidentWebhookEvent
	var timeline operationsdomain.IncidentTimelineEvent
	err := memoryGovernanceRead(ctx, r.uow, tenant, receiver, func(s *MemoryUnitOfWorkSnapshot) error {
		if event == "" || strings.TrimSpace(event) != event || !memoryGovernanceText(event, 1024) || len(tenant)+len(receiver)+len(event) > operationsapp.MaxIncidentWebhookReplayKeyBytes {
			return ErrValidation
		}
		found := false
		for key, v := range s.IncidentWebhookEvents {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.ReceiverID != receiver || v.EventID != event {
				continue
			}
			if found || v.ID == "" || v.ID != key {
				return ErrConflict
			}
			for _, field := range []struct {
				value string
				limit int
			}{{v.ID, 1024}, {v.IncidentID, 1024}, {v.Provider, 65536}, {v.PayloadHash, 71}, {v.SignatureHash, 71}, {v.TimelineEventID, 1024}, {v.Result, 128}, {v.SchemaVersion, 1024}} {
				if !memoryGovernanceText(field.value, field.limit) {
					return ErrConflict
				}
			}
			e, ok := s.IncidentTimelineEvents[v.TimelineEventID]
			if !ok || e.ID != v.TimelineEventID || e.TenantID != tenant {
				return ErrConflict
			}
			for _, field := range []struct {
				value string
				limit int
			}{{e.IncidentID, 1024}, {e.EventType, operationsapp.IncidentWebhookBodyLimit}, {e.Summary, operationsapp.IncidentWebhookBodyLimit}, {e.EvidenceID, 1024}, {e.SchemaVersion, 1024}} {
				if !memoryGovernanceText(field.value, field.limit) {
					return ErrConflict
				}
			}
			out = operationsdomain.IncidentWebhookEvent(v)
			out.CreatedAt = out.CreatedAt.UTC()
			timeline = operationsdomain.IncidentTimelineEvent(e)
			timeline.CreatedAt, timeline.OccurredAt = timeline.CreatedAt.UTC(), timeline.OccurredAt.UTC()
			found = true
		}
		if !found {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return operationsdomain.IncidentWebhookEvent{}, operationsdomain.IncidentTimelineEvent{}, err
	}
	return out, timeline, nil
}
