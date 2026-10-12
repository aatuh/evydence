package authz

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

const IncidentWebhookTimestampTolerance = 5 * time.Minute

// IncidentWebhookBinding is current locked receiver metadata. Keys, signatures
// and raw payloads stay at the cryptographic verification boundary, not here.
type IncidentWebhookBinding struct {
	TenantID, ReceiverID, IncidentID, Status, Provider string
}

// IncidentWebhookSubject contains resolved current ownership only. Zero
// evidence means no association; it does not grant tenant inventory access.
type IncidentWebhookSubject struct {
	ID, TenantID, Kind string
	Resources          ResourceReferences
}

type IncidentWebhookRequest struct {
	Action             Action
	Incident, Evidence IncidentWebhookSubject
	Timestamp, Now     time.Time
}

func webhookPolicyContext(ctx context.Context) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	return ctx.Err()
}

// CheckIncidentWebhookTimestamp applies the same inclusive five-minute window
// at preflight and after blocking storage reads. It does not verify signatures.
func CheckIncidentWebhookTimestamp(ctx context.Context, timestamp, now time.Time) error {
	if err := webhookPolicyContext(ctx); err != nil {
		return err
	}
	if timestamp.IsZero() || now.IsZero() || timestamp.Before(now.Add(-IncidentWebhookTimestampTolerance)) || timestamp.After(now.Add(IncidentWebhookTimestampTolerance)) {
		return ErrUnauthorized
	}
	return nil
}

// CheckIncidentWebhookBinding constrains a routed receiver before its public
// key can verify authority. Inactive, missing and foreign bindings share 404.
func CheckIncidentWebhookBinding(ctx context.Context, binding IncidentWebhookBinding, tenantID, receiverID string) error {
	if err := webhookPolicyContext(ctx); err != nil {
		return err
	}
	if !validPortalPolicyID(tenantID) || !validPortalPolicyID(receiverID) || !validPortalPolicyID(binding.IncidentID) || binding.TenantID != tenantID || binding.ReceiverID != receiverID || binding.Status != "active" || len(binding.Provider) > 65536 || !utf8.ValidString(binding.Provider) || strings.ContainsRune(binding.Provider, 0) || strings.TrimSpace(binding.Provider) == "" {
		return ErrNotFound
	}
	return nil
}

func validWebhookPolicySubject(subject IncidentWebhookSubject, tenant, kind string) bool {
	if !validPortalPolicyID(subject.ID) || subject.TenantID != tenant || subject.Kind != kind {
		return false
	}
	r := subject.Resources
	for _, id := range []string{r.ProductID, r.ProjectID, r.ReleaseID, r.BuildID, r.DeploymentID} {
		if id != "" && !validPortalPolicyID(id) {
			return false
		}
	}
	if kind == "incident" {
		return r.ProductID != "" && r == (ResourceReferences{ProductID: r.ProductID, ReleaseID: r.ReleaseID})
	}
	return r.ProductID != "" && r == (ResourceReferences{ProductID: r.ProductID, ProjectID: r.ProjectID, ReleaseID: r.ReleaseID, BuildID: r.BuildID, DeploymentID: r.DeploymentID})
}

// AuthorizeIncidentWebhook requires an already verified receiver signature.
// It permits one bound incident, never arbitrary tenant incidents or evidence.
// Product-wide evidence remains valid; release evidence must match the incident.
func AuthorizeIncidentWebhook(ctx context.Context, binding IncidentWebhookBinding, request IncidentWebhookRequest) error {
	if err := CheckIncidentWebhookTimestamp(ctx, request.Timestamp, request.Now); err != nil {
		return err
	}
	definition, ok := DefinitionFor(request.Action)
	if !ok || definition.Boundary != SignedWebhookBoundary {
		return ErrForbidden
	}
	if err := CheckIncidentWebhookBinding(ctx, binding, binding.TenantID, binding.ReceiverID); err != nil {
		return err
	}
	incident := request.Incident
	if !validWebhookPolicySubject(incident, binding.TenantID, "incident") || incident.ID != binding.IncidentID {
		return ErrNotFound
	}
	evidence := request.Evidence
	if evidence == (IncidentWebhookSubject{}) {
		return nil
	}
	if !validWebhookPolicySubject(evidence, binding.TenantID, "evidence") || evidence.Resources.ProductID != incident.Resources.ProductID || evidence.Resources.ReleaseID != "" && evidence.Resources.ReleaseID != incident.Resources.ReleaseID {
		return ErrNotFound
	}
	return nil
}
