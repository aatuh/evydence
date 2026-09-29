package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"time"

	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

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

type UploadSecurityScanInput struct {
	ProductID  string
	ReleaseID  string
	ArtifactID string
	Category   string
	Format     string
	Scanner    string
	TargetRef  string
	Raw        []byte
}

type UploadManualSecurityDocumentInput struct {
	ProductID    string
	ReleaseID    string
	DocumentType string
	Title        string
	Sensitivity  string
	Raw          []byte
	MediaType    string
}

type CreateSBOMDiffInput struct {
	BaseSBOMID   string
	TargetSBOMID string
	ReleaseID    string
}

type RecordVulnerabilityWorkflowInput struct {
	FindingID string
	Action    string
	Reason    string
}

type CreateContractDiffInput struct {
	BaseContractID   string
	TargetContractID string
	ReleaseID        string
}

type CreateCustomPolicyInput struct {
	Name        string
	Version     string
	Description string
	Rules       []domain.PolicyRule
}

const incidentWebhookTimestampTolerance = 5 * time.Minute

type cycloneDXVEXDocument struct {
	BOMFormat       string                      `json:"bomFormat"`
	SpecVersion     string                      `json:"specVersion"`
	Vulnerabilities []cycloneDXVEXVulnerability `json:"vulnerabilities"`
	Warnings        []string                    `json:"-"`
}

type cycloneDXVEXVulnerability struct {
	ID       string               `json:"id"`
	Affects  []cycloneDXVEXAffect `json:"affects,omitempty"`
	Analysis cycloneDXVEXAnalysis `json:"analysis"`
}

type cycloneDXVEXAffect struct {
	Ref string `json:"ref"`
}

type cycloneDXVEXAnalysis struct {
	State, Justification, Detail string
	Response                     []string
}

func parseCycloneDXVEX(raw []byte) (cycloneDXVEXDocument, error) {
	parsed, err := vexparser.ParseCycloneDX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
	if err != nil {
		return cycloneDXVEXDocument{}, ErrValidation
	}
	doc := cycloneDXVEXDocument{BOMFormat: "CycloneDX", SpecVersion: parsed.Version, Warnings: parsed.Warnings}
	for _, statement := range parsed.Statements {
		vulnerability := cycloneDXVEXVulnerability{ID: statement.Vulnerability, Analysis: cycloneDXVEXAnalysis{Justification: statement.Justification, Detail: statement.ImpactStatement}}
		switch statement.Status {
		case decisionStatusFixed:
			vulnerability.Analysis.State = "resolved"
		case decisionStatusNotAffected:
			vulnerability.Analysis.State = "not_affected"
		case decisionStatusAffected:
			vulnerability.Analysis.State = "exploitable"
		case decisionStatusUnderInvestigation:
			vulnerability.Analysis.State = "in_triage"
		}
		if statement.ActionStatement != "" {
			vulnerability.Analysis.Response = strings.Split(statement.ActionStatement, ",")
		}
		for _, product := range statement.Products {
			vulnerability.Affects = append(vulnerability.Affects, cycloneDXVEXAffect{Ref: product})
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, vulnerability)
	}
	return doc, nil
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

func incidentWebhookSignedPayload(timestamp time.Time, eventID string, body []byte) []byte {
	prefix := timestamp.UTC().Format(time.RFC3339) + "\n" + strings.TrimSpace(eventID) + "\n"
	return append([]byte(prefix), body...)
}

func decodeWebhookPublicKey(value string) ([]byte, error) {
	key, err := decodeBase64Value(strings.TrimSpace(value))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrValidation
	}
	return key, nil
}

func decodeWebhookSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "ed25519=")
	signature, err := decodeBase64Value(value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrUnauthorized
	}
	return signature, nil
}

func decodeBase64Value(value string) ([]byte, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
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

func (s packageReportService) IncidentReport(ctx context.Context, actor domain.Actor, incidentID string) (domain.IncidentReport, error) {
	l := s.ledger
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

func (l *Ledger) UploadSecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	value, err := l.evidenceCommands.UploadSecurityScan(ctx, actor, evidenceapp.UploadSecurityScanInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Category: in.Category,
		Format: in.Format, Scanner: in.Scanner, TargetRef: in.TargetRef, Raw: append([]byte(nil), in.Raw...),
	})
	return securityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadAPISecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	value, err := l.evidenceCommands.UploadAPISecurityScan(ctx, actor, evidenceapp.UploadSecurityScanInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Category: in.Category,
		Format: in.Format, Scanner: in.Scanner, TargetRef: in.TargetRef, Raw: append([]byte(nil), in.Raw...),
	})
	return securityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadManualSecurityDocument(ctx context.Context, actor domain.Actor, in UploadManualSecurityDocumentInput) (domain.ManualSecurityDocument, error) {
	value, err := l.evidenceCommands.UploadManualSecurityDocument(ctx, actor, evidenceapp.UploadManualSecurityDocumentInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, DocumentType: in.DocumentType, Title: in.Title,
		Sensitivity: in.Sensitivity, Raw: append([]byte(nil), in.Raw...), MediaType: in.MediaType,
	})
	return manualSecurityDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) CreateSBOMDiff(ctx context.Context, actor domain.Actor, in CreateSBOMDiffInput) (domain.SBOMDiff, error) {
	value, err := l.evidenceCommands.CreateSBOMDiff(ctx, actor, evidenceapp.CreateSBOMDiffInput{
		BaseSBOMID: in.BaseSBOMID, TargetSBOMID: in.TargetSBOMID, ReleaseID: in.ReleaseID,
	})
	return sbomDiffFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadCycloneDXVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	value, err := l.evidenceCommands.UploadCycloneDXVEX(ctx, actor, releaseID, artifactID, raw)
	return vexDocumentFromEvidenceContext(value), fromEvidenceContextError(err)
}
func (l *Ledger) PreviewCycloneDXVEXImport(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXImportPreview, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if !ValidPayloadSize(int64(len(raw)), EvidenceDocumentLimit) {
		return domain.VEXImportPreview{}, ErrValidation
	}
	doc, err := parseCycloneDXVEX(raw)
	if err != nil || len(doc.Vulnerabilities) == 0 {
		return domain.VEXImportPreview{}, ErrValidation
	}
	statusSummary, invalidStatements, validStatements := analyzeCycloneDXVEXStatements(doc)
	if len(validStatements) == 0 {
		return domain.VEXImportPreview{}, ErrValidation
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if releaseID == "" {
		return domain.VEXImportPreview{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if err := l.ensureScopeLocked(actor.TenantID, "", "", releaseID); err != nil {
		return domain.VEXImportPreview{}, err
	}
	if artifactID != "" {
		artifact, ok := l.artifacts[artifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			return domain.VEXImportPreview{}, ErrNotFound
		}
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: releaseID}); err != nil {
		return domain.VEXImportPreview{}, err
	}
	created, superseded, warnings, mappingFailures := l.previewCycloneDXVEXDecisionEffectsLocked(actor.TenantID, releaseID, validStatements)
	warnings = append(append([]string{}, doc.Warnings...), warnings...)
	if len(invalidStatements) > 0 {
		warnings = append(warnings, "One or more CycloneDX VEX vulnerabilities were skipped because required analysis fields were missing or unsupported.")
	}
	return domain.VEXImportPreview{
		TenantID:                actor.TenantID,
		ReleaseID:               releaseID,
		ArtifactID:              artifactID,
		Format:                  "cyclonedx",
		ParserVersion:           ParserVersionCycloneDXVEXJSON,
		Advisory:                true,
		StatementCount:          len(doc.Vulnerabilities),
		StatusSummary:           cloneIntMap(statusSummary),
		DecisionsWouldCreate:    created,
		DecisionsWouldSupersede: superseded,
		Warnings:                warnings,
		InvalidStatements:       invalidStatements,
		MappingFailures:         mappingFailures,
		Assumptions:             vexImportPreviewAssumptions(),
		Limitations:             vexImportPreviewLimitations(),
		SchemaVersion:           domain.VEXImportPreviewSchemaVersion,
		GeneratedAt:             l.now(),
	}, nil
}

type cycloneDXVEXStatement struct {
	index         int
	vulnerability cycloneDXVEXVulnerability
	status        string
	affectedRefs  map[string]struct{}
}

func analyzeCycloneDXVEXStatements(doc cycloneDXVEXDocument) (map[string]int, []domain.VEXImportIssue, []cycloneDXVEXStatement) {
	statusSummary := map[string]int{}
	invalid := []domain.VEXImportIssue{}
	valid := []cycloneDXVEXStatement{}
	for index, vuln := range doc.Vulnerabilities {
		vuln.ID = strings.TrimSpace(vuln.ID)
		status := cyclonedxAnalysisStatus(vuln.Analysis.State)
		switch {
		case vuln.ID == "":
			invalid = append(invalid, vexImportIssue(index+1, "missing_vulnerability", "CycloneDX VEX vulnerability is missing an id."))
			continue
		case status == "":
			invalid = append(invalid, vexImportIssue(index+1, "unsupported_analysis_state", "CycloneDX VEX vulnerability has an unsupported analysis state."))
			continue
		}
		statusSummary[status]++
		valid = append(valid, cycloneDXVEXStatement{index: index + 1, vulnerability: vuln, status: status, affectedRefs: cycloneDXVEXAffectedRefs(vuln)})
	}
	return statusSummary, invalid, valid
}

func cycloneDXVEXAffectedRefs(vuln cycloneDXVEXVulnerability) map[string]struct{} {
	out := map[string]struct{}{}
	for _, affect := range vuln.Affects {
		if ref := strings.TrimSpace(affect.Ref); ref != "" {
			out[ref] = struct{}{}
		}
	}
	return out
}

func (l *Ledger) findCycloneDXVEXMatchingFindingsLocked(tenantID, releaseID string, statement cycloneDXVEXStatement) ([]matchedFinding, bool) {
	out := []matchedFinding{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if finding.Vulnerability != statement.vulnerability.ID {
				continue
			}
			if len(statement.affectedRefs) > 0 && finding.Component != "" {
				if _, ok := statement.affectedRefs[finding.Component]; !ok {
					continue
				}
			}
			out = append(out, matchedFinding{scan: scan, finding: finding})
		}
	}
	return unambiguousVEXMatches(out, statement.affectedRefs)
}

func (l *Ledger) previewCycloneDXVEXDecisionEffectsLocked(tenantID, releaseID string, statements []cycloneDXVEXStatement) (int, int, []string, []domain.VEXImportIssue) {
	created, superseded := 0, 0
	mappingFailures := []domain.VEXImportIssue{}
	warnings := []string{}
	createdForFinding := map[string]struct{}{}
	duplicateWarningAdded := false
	for _, statement := range statements {
		matches, ambiguous := l.findCycloneDXVEXMatchingFindingsLocked(tenantID, releaseID, statement)
		if ambiguous {
			mappingFailures = append(mappingFailures, vexImportIssue(statement.index, "ambiguous_finding", "Multiple plausible findings matched this CycloneDX VEX vulnerability; no decision would be applied."))
			continue
		}
		if len(matches) == 0 {
			mappingFailures = append(mappingFailures, vexImportIssue(statement.index, "finding_not_found", "No matching vulnerability scan finding was found for this CycloneDX VEX vulnerability."))
		}
		added, replaced, duplicate := l.previewDecisionEffectsForMatchesLocked(tenantID, matches, createdForFinding)
		created += added
		superseded += replaced
		if duplicate && !duplicateWarningAdded {
			warnings = append(warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.")
			duplicateWarningAdded = true
		}
	}
	return created, superseded, warnings, mappingFailures
}

func (l *Ledger) RecordVulnerabilityWorkflow(ctx context.Context, actor domain.Actor, in RecordVulnerabilityWorkflowInput) (domain.VulnerabilityWorkflowRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	if err := require(actor, ScopeSecurityWrite); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	in.FindingID, in.Action, in.Reason = strings.TrimSpace(in.FindingID), strings.TrimSpace(in.Action), strings.TrimSpace(in.Reason)
	if in.FindingID == "" || !validVulnWorkflowAction(in.Action) || in.Reason == "" {
		return domain.VulnerabilityWorkflowRecord{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	scan, _, ok := l.findFindingLocked(actor.TenantID, in.FindingID)
	if !ok {
		return domain.VulnerabilityWorkflowRecord{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	record := domain.VulnerabilityWorkflowRecord{ID: newID("vw"), TenantID: actor.TenantID, FindingID: in.FindingID, ReleaseID: scan.ReleaseID, Action: in.Action, Reason: in.Reason, ActorID: actorID(actor), SchemaVersion: "vulnerability-workflow.v1.0.0", CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertVulnerabilityWorkflow(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "vulnerability_workflow."+record.Action, "vulnerability_finding", record.FindingID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.VulnerabilityWorkflowRecord{}, err
		}
		l.vulnWorkflow[record.ID] = record
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	l.vulnWorkflow[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "vulnerability_workflow."+record.Action, "vulnerability_finding", in.FindingID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	return record, nil
}

func (s packageReportService) VulnerabilityPostureReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityPostureReport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityPostureReport{}, err
	}
	if err := require(actor, ScopeSecurityRead); err != nil {
		return domain.VulnerabilityPostureReport{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if releaseID == "" {
		if err := l.authorizeResourceLocked(actor, ScopeSecurityRead, resourceRefs{}); err != nil {
			return domain.VulnerabilityPostureReport{}, err
		}
	}
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VulnerabilityPostureReport{}, err
	}
	if releaseID != "" {
		release, ok := l.releases[releaseID]
		if !ok || release.TenantID != actor.TenantID {
			return domain.VulnerabilityPostureReport{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeSecurityRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
			return domain.VulnerabilityPostureReport{}, err
		}
	}
	summary := map[string]int{}
	openCritical := 0
	for _, scan := range l.scans {
		if scan.TenantID != actor.TenantID || (releaseID != "" && scan.ReleaseID != releaseID) {
			continue
		}
		for _, finding := range scan.Findings {
			summary[strings.ToLower(finding.Severity)]++
			if strings.EqualFold(finding.Severity, "critical") && strings.EqualFold(finding.State, "open") {
				openCritical++
			}
		}
	}
	return domain.VulnerabilityPostureReport{ReportType: "vulnerability_posture", TemplateVersion: "vulnerability-posture.v1.0.0", ReleaseID: releaseID, Summary: summary, OpenCritical: openCritical, Assumptions: []string{"Posture reflects scans uploaded to this tenant only."}, Limitations: []string{"Scanner coverage and vulnerability databases are not independently verified by Evydence."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) CreateContractDiff(ctx context.Context, actor domain.Actor, in CreateContractDiffInput) (domain.ContractDiff, error) {
	value, err := l.evidenceCommands.CreateContractDiff(ctx, actor, evidenceapp.CreateContractDiffInput{
		BaseContractID: in.BaseContractID, TargetContractID: in.TargetContractID, ReleaseID: in.ReleaseID,
	})
	return contractDiffFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) CreateCustomPolicy(ctx context.Context, actor domain.Actor, in CreateCustomPolicyInput) (domain.CustomPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomPolicy{}, err
	}
	if err := require(actor, ScopePolicyWrite); err != nil {
		return domain.CustomPolicy{}, err
	}
	in.Name, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || len(in.Rules) == 0 {
		return domain.CustomPolicy{}, ErrValidation
	}
	for _, rule := range in.Rules {
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Severity) == "" {
			return domain.CustomPolicy{}, ErrValidation
		}
		if rule.EvidenceType != "" && !validPolicyEvidenceType(rule.EvidenceType) {
			return domain.CustomPolicy{}, ErrValidation
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.customPolicies {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name && existing.Version == in.Version {
			return domain.CustomPolicy{}, ErrConflict
		}
	}
	policy := domain.CustomPolicy{ID: newID("cpol"), TenantID: actor.TenantID, Name: in.Name, Version: in.Version, Description: strings.TrimSpace(in.Description), Rules: append([]domain.PolicyRule(nil), in.Rules...), SchemaVersion: domain.CustomPolicySchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertCustomPolicy(ctx, policy); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(policy.CreatedAt, actor.TenantID, "custom_policy.created", "custom_policy", policy.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.CustomPolicy{}, err
		}
		l.customPolicies[policy.ID] = policy
		l.publishCommittedAuditEntryLocked(entry)
		return policy, nil
	}
	l.customPolicies[policy.ID] = policy
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.created", "custom_policy", policy.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomPolicy{}, err
	}
	return policy, nil
}

func (l *Ledger) EvaluateCustomPolicy(ctx context.Context, actor domain.Actor, policyID, releaseID string) (domain.CustomPolicyEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	if err := require(actor, ScopePolicyRead); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	policy, ok := l.customPolicies[strings.TrimSpace(policyID)]
	release, rok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || !rok || policy.TenantID != actor.TenantID || release.TenantID != actor.TenantID {
		return domain.CustomPolicyEvaluation{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopePolicyRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	checks := []domain.PolicyCheck{}
	result := "passed"
	for _, rule := range policy.Rules {
		check := l.evaluatePolicyRuleLocked(actor.TenantID, release.ID, rule)
		checks = append(checks, check)
		if check.Result == "failed" {
			result = "failed"
		}
	}
	inputHash, err := canonicalAnyHash(map[string]any{"policy": policy, "release_id": release.ID, "checks": checks})
	if err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	eval := domain.CustomPolicyEvaluation{ID: newID("cpe"), TenantID: actor.TenantID, PolicyID: policy.ID, ReleaseID: release.ID, Result: result, Checks: checks, InputHash: inputHash, SchemaVersion: domain.CustomPolicyEvalSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertCustomPolicyEvaluation(ctx, eval); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(eval.CreatedAt, actor.TenantID, "custom_policy.evaluated", "custom_policy_evaluation", eval.ID, "api_key", actor.KeyID, inputHash, ""))
			return err
		}); err != nil {
			return domain.CustomPolicyEvaluation{}, err
		}
		l.customPolicyEvals[eval.ID] = eval
		l.publishCommittedAuditEntryLocked(entry)
		return eval, nil
	}
	l.customPolicyEvals[eval.ID] = eval
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.evaluated", "custom_policy_evaluation", eval.ID, "api_key", actor.KeyID, inputHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	return eval, nil
}

func cyclonedxAnalysisStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "resolved":
		return "fixed"
	case "not_affected":
		return "not_affected"
	case "exploitable", "in_triage":
		return "affected"
	default:
		return ""
	}
}

func (l *Ledger) evaluatePolicyRuleLocked(tenantID, releaseID string, rule domain.PolicyRule) domain.PolicyCheck {
	if rule.EvidenceType == "" {
		return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: "metadata-only custom policy rule recorded"}
	}
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && item.Type == rule.EvidenceType {
			return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: rule.EvidenceType + " evidence exists"}
		}
	}
	if rule.Required {
		return domain.PolicyCheck{Name: rule.Name, Result: "failed", Severity: rule.Severity, Missing: []string{rule.EvidenceType}, Explanation: rule.EvidenceType + " evidence is missing"}
	}
	return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: "optional evidence not present"}
}

func validSeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validSecurityScanCategory(category string) bool {
	switch category {
	case "sast", "dast", "secret_scan", "license_scan", "api_security":
		return true
	default:
		return false
	}
}

func validManualDocType(typ string) bool {
	switch typ {
	case "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

func validSensitivity(value string) bool {
	switch value {
	case "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func validVulnWorkflowAction(action string) bool {
	switch action {
	case "scanner_metadata", "sla_set", "scanner_disagreement", "superseded", "reopened":
		return true
	default:
		return false
	}
}

func validPolicyEvidenceType(typ string) bool {
	switch typ {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception", "sast", "dast", "secret_scan", "license_scan", "api_security", "deployment", "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

func validContractDiffResult(result string) bool {
	switch result {
	case "unchanged", "changed", "breaking":
		return true
	default:
		return false
	}
}
