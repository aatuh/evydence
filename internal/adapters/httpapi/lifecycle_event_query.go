package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func lifecycleEventFromQuery(event evidencedomain.EvidenceLifecycleEvent) domain.EvidenceLifecycleEvent {
	details := make(map[string]any, len(event.Details))
	for key, value := range event.Details {
		if key != evidencedomain.LegacyCanonicalOriginDetailKey {
			details[key] = value
		}
	}
	safe, _ := redaction.RemoveSensitive(details)
	safeDetails, _ := safe.(map[string]any)
	return domain.EvidenceLifecycleEvent{
		ID: event.ID, TenantID: event.TenantID, EvidenceID: event.EvidenceID,
		Action: event.Action.String(), Reason: redaction.RedactString(event.Reason),
		Details: safeDetails, ReplacementID: event.ReplacementID, ActorID: event.ActorID,
		SchemaVersion: event.SchemaVersion, CreatedAt: event.CreatedAt,
	}
}
