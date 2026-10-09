package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// Unchanged historical incident and callback algorithms; never production wiring.
type CreateIncidentInput struct {
	ProductID string
	ReleaseID string
	Title     string
	Severity  string
	OpenedAt  time.Time
}

type RecordIncidentTimelineInput struct {
	EventType  string
	Summary    string
	EvidenceID string
	OccurredAt time.Time
}

type CreateIncidentWebhookReceiverInput struct {
	IncidentID string
	Name       string
	Provider   string
	PublicKey  string
}

type HandleIncidentWebhookInput struct {
	ReceiverID string
	EventID    string
	Timestamp  time.Time
	Signature  string
	Body       []byte
}

type CreateRemediationTaskInput struct {
	IncidentID string
	ReleaseID  string
	Title      string
	Owner      string
	DueAt      *time.Time
	EvidenceID string
}

func (l *Ledger) CreateIncident(ctx context.Context, actor domain.Actor, in CreateIncidentInput) (domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return domain.Incident{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.Incident{}, err
	}
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	in.Title, in.Severity = strings.TrimSpace(in.Title), strings.ToLower(strings.TrimSpace(in.Severity))
	if in.ProductID == "" || in.Title == "" || !validSeverity(in.Severity) {
		return domain.Incident{}, ErrValidation
	}
	if in.OpenedAt.IsZero() {
		in.OpenedAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.Incident{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.Incident{}, err
	}
	incident := domain.Incident{
		ID:            newID("inc"),
		TenantID:      actor.TenantID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Title:         in.Title,
		Severity:      in.Severity,
		Status:        "open",
		OpenedAt:      in.OpenedAt.UTC(),
		SchemaVersion: domain.IncidentSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertIncident(ctx, incident); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(incident.CreatedAt, actor.TenantID, "incident.created", "incident", incident.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.Incident{}, err
		}
		l.incidents[incident.ID] = incident
		l.publishCommittedAuditEntryLocked(entry)
		return incident, nil
	}
	l.incidents[incident.ID] = incident
	_, _ = l.appendChainLocked(actor.TenantID, "incident.created", "incident", incident.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Incident{}, err
	}
	return incident, nil
}

func (l *Ledger) RecordIncidentTimelineEvent(ctx context.Context, actor domain.Actor, incidentID string, in RecordIncidentTimelineInput) (domain.IncidentTimelineEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	in.EventType, in.Summary = strings.TrimSpace(in.EventType), strings.TrimSpace(in.Summary)
	if in.EventType == "" || in.Summary == "" {
		return domain.IncidentTimelineEvent{}, ErrValidation
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	incident, ok := l.incidents[strings.TrimSpace(incidentID)]
	if !ok || incident.TenantID != actor.TenantID {
		return domain.IncidentTimelineEvent{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	if in.EvidenceID != "" {
		item, ok := l.evidence[strings.TrimSpace(in.EvidenceID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.IncidentTimelineEvent{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, refsForEvidence(item)); err != nil {
			return domain.IncidentTimelineEvent{}, err
		}
	}
	event := domain.IncidentTimelineEvent{
		ID:            newID("it"),
		TenantID:      actor.TenantID,
		IncidentID:    incident.ID,
		EventType:     in.EventType,
		Summary:       in.Summary,
		EvidenceID:    strings.TrimSpace(in.EvidenceID),
		OccurredAt:    in.OccurredAt.UTC(),
		SchemaVersion: domain.IncidentTimelineSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertIncidentTimelineEvent(ctx, event); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(event.CreatedAt, actor.TenantID, "incident.timeline_recorded", "incident", incident.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.IncidentTimelineEvent{}, err
		}
		l.timeline[event.ID] = event
		l.publishCommittedAuditEntryLocked(entry)
		return event, nil
	}
	l.timeline[event.ID] = event
	_, _ = l.appendChainLocked(actor.TenantID, "incident.timeline_recorded", "incident", incident.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	return event, nil
}

func (l *Ledger) CreateIncidentWebhookReceiver(ctx context.Context, actor domain.Actor, in CreateIncidentWebhookReceiverInput) (domain.IncidentWebhookReceiver, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentWebhookReceiver{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.IncidentWebhookReceiver{}, err
	}
	in.IncidentID = strings.TrimSpace(in.IncidentID)
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.TrimSpace(in.Provider)
	in.PublicKey = strings.TrimSpace(in.PublicKey)
	publicKey, err := decodeWebhookPublicKey(in.PublicKey)
	if err != nil || in.IncidentID == "" || in.Name == "" || in.Provider == "" {
		return domain.IncidentWebhookReceiver{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	incident, ok := l.incidents[in.IncidentID]
	if !ok || incident.TenantID != actor.TenantID {
		return domain.IncidentWebhookReceiver{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
		return domain.IncidentWebhookReceiver{}, err
	}
	receiver := domain.IncidentWebhookReceiver{
		ID:            newID("iwr"),
		TenantID:      actor.TenantID,
		IncidentID:    incident.ID,
		Name:          in.Name,
		Provider:      in.Provider,
		PublicKey:     base64.RawStdEncoding.EncodeToString(publicKey),
		Status:        "active",
		SchemaVersion: domain.IncidentWebhookReceiverVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertIncidentWebhookReceiver(ctx, receiver); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(receiver.CreatedAt, actor.TenantID, "incident_webhook_receiver.created", "incident_webhook_receiver", receiver.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.IncidentWebhookReceiver{}, err
		}
		l.webhookReceivers[receiver.ID] = receiver
		l.publishCommittedAuditEntryLocked(entry)
		return receiver, nil
	}
	l.webhookReceivers[receiver.ID] = receiver
	_, _ = l.appendChainLocked(actor.TenantID, "incident_webhook_receiver.created", "incident_webhook_receiver", receiver.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.IncidentWebhookReceiver{}, err
	}
	return receiver, nil
}

func (l *Ledger) HandleIncidentWebhook(ctx context.Context, in HandleIncidentWebhookInput) (domain.IncidentWebhookEvent, domain.IncidentTimelineEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, err
	}
	in.ReceiverID = strings.TrimSpace(in.ReceiverID)
	in.EventID = strings.TrimSpace(in.EventID)
	in.Signature = strings.TrimSpace(in.Signature)
	if in.ReceiverID == "" || in.EventID == "" || in.Timestamp.IsZero() || in.Signature == "" || len(in.Body) == 0 || len(in.Body) > 2<<20 {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrValidation
	}
	now := l.now()
	if in.Timestamp.Before(now.Add(-incidentWebhookTimestampTolerance)) || in.Timestamp.After(now.Add(incidentWebhookTimestampTolerance)) {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrUnauthorized
	}
	payloadHash := hashBytes(in.Body)
	signatureBytes, err := decodeWebhookSignature(in.Signature)
	if err != nil {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrUnauthorized
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	receiver, ok := l.webhookReceivers[in.ReceiverID]
	if !ok || receiver.Status != "active" {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrNotFound
	}
	publicKey, err := decodeWebhookPublicKey(receiver.PublicKey)
	if err != nil {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrUnauthorized
	}
	signedPayload := incidentWebhookSignedPayload(in.Timestamp, in.EventID, in.Body)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signedPayload, signatureBytes) {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrUnauthorized
	}
	for _, existing := range l.webhookEvents {
		if existing.ReceiverID != receiver.ID || existing.EventID != in.EventID {
			continue
		}
		if existing.PayloadHash != payloadHash {
			return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrConflict
		}
		timeline, ok := l.timeline[existing.TimelineEventID]
		if !ok {
			return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrConflict
		}
		return existing, timeline, nil
	}
	incident, ok := l.incidents[receiver.IncidentID]
	if !ok || incident.TenantID != receiver.TenantID {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrNotFound
	}
	var payload struct {
		EventType  string    `json:"event_type"`
		Summary    string    `json:"summary"`
		EvidenceID string    `json:"evidence_id"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(in.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrValidation
	}
	payload.EventType = strings.TrimSpace(payload.EventType)
	payload.Summary = strings.TrimSpace(payload.Summary)
	payload.EvidenceID = strings.TrimSpace(payload.EvidenceID)
	if payload.EventType == "" || payload.Summary == "" {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrValidation
	}
	if payload.OccurredAt.IsZero() {
		payload.OccurredAt = now
	}
	if payload.EvidenceID != "" {
		item, ok := l.evidence[payload.EvidenceID]
		if !ok || item.TenantID != receiver.TenantID || (item.ReleaseID != "" && item.ReleaseID != incident.ReleaseID) {
			return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, ErrNotFound
		}
	}
	timeline := domain.IncidentTimelineEvent{
		ID:            newID("it"),
		TenantID:      receiver.TenantID,
		IncidentID:    incident.ID,
		EventType:     payload.EventType,
		Summary:       payload.Summary,
		EvidenceID:    payload.EvidenceID,
		OccurredAt:    payload.OccurredAt.UTC(),
		SchemaVersion: domain.IncidentTimelineSchemaVersion,
		CreatedAt:     now,
	}
	record := domain.IncidentWebhookEvent{
		ID:              newID("iwe"),
		TenantID:        receiver.TenantID,
		ReceiverID:      receiver.ID,
		IncidentID:      incident.ID,
		Provider:        receiver.Provider,
		EventID:         in.EventID,
		PayloadHash:     payloadHash,
		SignatureHash:   hashBytes(signatureBytes),
		TimelineEventID: timeline.ID,
		Result:          "accepted",
		SchemaVersion:   domain.IncidentWebhookEventVersion,
		CreatedAt:       now,
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertIncidentWebhookEvent(ctx, record, timeline); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, receiver.TenantID, "incident.webhook_timeline_recorded", "incident", incident.ID, "webhook", receiver.ID, payloadHash, ""))
			return err
		}); err != nil {
			return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, err
		}
		l.timeline[timeline.ID] = timeline
		l.webhookEvents[record.ID] = record
		l.publishCommittedAuditEntryLocked(entry)
		return record, timeline, nil
	}
	l.timeline[timeline.ID] = timeline
	l.webhookEvents[record.ID] = record
	_, _ = l.appendChainLocked(receiver.TenantID, "incident.webhook_timeline_recorded", "incident", incident.ID, "webhook", receiver.ID, payloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.IncidentWebhookEvent{}, domain.IncidentTimelineEvent{}, err
	}
	return record, timeline, nil
}

func (l *Ledger) CreateRemediationTask(ctx context.Context, actor domain.Actor, in CreateRemediationTaskInput) (domain.RemediationTask, error) {
	if err := ctx.Err(); err != nil {
		return domain.RemediationTask{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.RemediationTask{}, err
	}
	in.IncidentID, in.ReleaseID = strings.TrimSpace(in.IncidentID), strings.TrimSpace(in.ReleaseID)
	in.Title, in.Owner = strings.TrimSpace(in.Title), strings.TrimSpace(in.Owner)
	if in.Title == "" || in.Owner == "" || (in.IncidentID == "" && in.ReleaseID == "") {
		return domain.RemediationTask{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.IncidentID != "" {
		incident, ok := l.incidents[in.IncidentID]
		if !ok || incident.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	if in.ReleaseID != "" {
		release, ok := l.releases[in.ReleaseID]
		if !ok || release.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	if in.EvidenceID != "" {
		item, ok := l.evidence[strings.TrimSpace(in.EvidenceID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, refsForEvidence(item)); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	task := domain.RemediationTask{
		ID:            newID("rt"),
		TenantID:      actor.TenantID,
		IncidentID:    in.IncidentID,
		ReleaseID:     in.ReleaseID,
		Title:         in.Title,
		Owner:         in.Owner,
		Status:        "open",
		DueAt:         in.DueAt,
		EvidenceID:    strings.TrimSpace(in.EvidenceID),
		SchemaVersion: domain.RemediationTaskSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertRemediationTask(ctx, task); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(task.CreatedAt, actor.TenantID, "remediation_task.created", "remediation_task", task.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.RemediationTask{}, err
		}
		l.tasks[task.ID] = task
		l.publishCommittedAuditEntryLocked(entry)
		return task, nil
	}
	l.tasks[task.ID] = task
	_, _ = l.appendChainLocked(actor.TenantID, "remediation_task.created", "remediation_task", task.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RemediationTask{}, err
	}
	return task, nil
}

func incidentWebhookSignedPayload(timestamp time.Time, eventID string, body []byte) []byte {
	return operationsapp.IncidentWebhookSignedPayload(timestamp, eventID, body)
}

func decodeWebhookPublicKey(value string) ([]byte, error) {
	key, err := operationsapp.DecodeIncidentWebhookPublicKey(value)
	if err != nil {
		return nil, ErrValidation
	}
	return key, nil
}

func decodeWebhookSignature(value string) ([]byte, error) {
	signature, err := operationsapp.DecodeIncidentWebhookSignature(value)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return signature, nil
}

const incidentWebhookTimestampTolerance = operationsapp.IncidentWebhookTimestampTolerance
