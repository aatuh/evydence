package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const IncidentWebhookBodyLimit = 2 << 20
const IncidentWebhookTimestampTolerance = 5 * time.Minute

// Leave room below PostgreSQL's B-tree tuple limit for the natural replay key.
const MaxIncidentWebhookReplayKeyBytes = 2304

// Routing exposes only a receiver's tenant locator, before provider identity is
// known. The transaction must re-read and lock the receiver by tenant and ID.
type IncidentWebhookRouting interface {
	LookupIncidentWebhookTenant(context.Context, string) (string, error)
}
type IncidentWebhookReader interface {
	ReadIncidentWebhookReceiver(context.Context, string, string) (operationsdomain.IncidentWebhookReceiver, error)
	ReadIncidentWebhookReplay(context.Context, string, string, string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error)
}
type IncidentWebhookTransaction interface {
	IncidentReader
	IncidentWebhookReader
	application.Authorizer
	application.AuditAppender
	InsertIncidentWebhookReceiver(context.Context, operationsdomain.IncidentWebhookReceiver) error
	InsertIncidentWebhookEvent(context.Context, operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent) error
}
type IncidentWebhookTransactions interface {
	ExecuteIncidentWebhook(context.Context, func(context.Context, IncidentWebhookTransaction) error) error
}
type IncidentWebhookCommandConfig struct {
	Transactions IncidentWebhookTransactions
	Routing      IncidentWebhookRouting
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type IncidentWebhookCommands struct{ config IncidentWebhookCommandConfig }
type CreateIncidentWebhookReceiverInput struct{ IncidentID, Name, Provider, PublicKey string }
type HandleIncidentWebhookInput struct {
	ReceiverID, EventID, Signature string
	Timestamp                      time.Time
	Body                           []byte
}

func NewIncidentWebhookCommands(c IncidentWebhookCommandConfig) (*IncidentWebhookCommands, error) {
	if c.Transactions == nil || c.Routing == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &IncidentWebhookCommands{c}, nil
}

// These pure protocol functions are shared with the explicit local-memory
// profile. RFC3339 UTC seconds and exact raw body bytes remain the signing
// contract, including for timestamps supplied with fractional seconds.
func IncidentWebhookSignedPayload(timestamp time.Time, eventID string, body []byte) []byte {
	return append([]byte(timestamp.UTC().Format(time.RFC3339)+"\n"+strings.TrimSpace(eventID)+"\n"), body...)
}
func decodeIncidentWebhookBase64(v string) ([]byte, error) {
	if len(v) > 1024 || strings.ContainsAny(v, "\r\n") {
		return nil, ErrValidation
	}
	if b, err := base64.RawStdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(v)
}
func DecodeIncidentWebhookPublicKey(v string) ([]byte, error) {
	b, err := decodeIncidentWebhookBase64(strings.TrimSpace(v))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrValidation
	}
	return b, nil
}
func DecodeIncidentWebhookSignature(v string) ([]byte, error) {
	b, err := decodeIncidentWebhookBase64(strings.TrimPrefix(strings.TrimSpace(v), "ed25519="))
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, application.ErrUnauthorized
	}
	return b, nil
}
func (c *IncidentWebhookCommands) prepareReceiver(ctx context.Context, a identitydomain.Actor, in CreateIncidentWebhookReceiverInput) (CreateIncidentWebhookReceiverInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := prepareIncidentActor(ctx, a, c.config.Authorizer); err != nil {
		return in, err
	}
	if !validEnvironmentText(in.IncidentID, 1024) || !validEnvironmentText(in.Name, 65536) || !validEnvironmentText(in.Provider, 65536) || !validEnvironmentText(in.PublicKey, 1024) {
		return in, ErrValidation
	}
	in.IncidentID, in.Name, in.Provider = strings.TrimSpace(in.IncidentID), strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider)
	key, err := DecodeIncidentWebhookPublicKey(in.PublicKey)
	if err != nil || in.IncidentID == "" || in.Name == "" || in.Provider == "" {
		return in, ErrValidation
	}
	in.PublicKey = base64.RawStdEncoding.EncodeToString(key)
	return in, nil
}
func authorizeWebhookReceiver(ctx context.Context, tx IncidentWebhookTransaction, a identitydomain.Actor, id string) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, ScopeOnly: true}); err != nil {
		return err
	}
	v, err := tx.ReadIncidentSubject(ctx, a.TenantID, "incident", id)
	if err != nil {
		return err
	}
	if !validIncidentSubject(v, a.TenantID, "incident", id) {
		return ErrNotFound
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, Resources: v.Resources})
}
func (c *IncidentWebhookCommands) execute(ctx context.Context, fn func(context.Context, IncidentWebhookTransaction) error) error {
	return c.config.Transactions.ExecuteIncidentWebhook(ctx, func(ctx context.Context, tx IncidentWebhookTransaction) error {
		if err := incidentContextError(ctx); err != nil {
			return err
		}
		if tx == nil {
			return ErrValidation
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return incidentContextError(ctx)
	})
}
func (c *IncidentWebhookCommands) AuthorizeCreateIncidentWebhookReceiver(ctx context.Context, a identitydomain.Actor, in CreateIncidentWebhookReceiverInput) error {
	in, err := c.prepareReceiver(ctx, a, in)
	if err != nil {
		return err
	}
	return c.execute(ctx, func(ctx context.Context, tx IncidentWebhookTransaction) error {
		return authorizeWebhookReceiver(ctx, tx, a, in.IncidentID)
	})
}
func (c *IncidentWebhookCommands) appendAudit(ctx context.Context, tx IncidentWebhookTransaction, e application.AuditEvent) error {
	e.ID = c.config.IDs.NewID("ace")
	if !validIncidentID(e.ID) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, e)
	return err
}
func (c *IncidentWebhookCommands) CreateIncidentWebhookReceiver(ctx context.Context, a identitydomain.Actor, in CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error) {
	in, err := c.prepareReceiver(ctx, a, in)
	if err != nil {
		return operationsdomain.IncidentWebhookReceiver{}, err
	}
	var out operationsdomain.IncidentWebhookReceiver
	err = c.execute(ctx, func(ctx context.Context, tx IncidentWebhookTransaction) error {
		if err := authorizeWebhookReceiver(ctx, tx, a, in.IncidentID); err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		out = operationsdomain.IncidentWebhookReceiver{ID: c.config.IDs.NewID("iwr"), TenantID: a.TenantID, IncidentID: in.IncidentID, Name: in.Name, Provider: in.Provider, PublicKey: in.PublicKey, Status: "active", SchemaVersion: operationsdomain.IncidentWebhookReceiverVersion, CreatedAt: now}
		if !validIncidentID(out.ID) || !incidentTime(now) {
			return ErrValidation
		}
		if err := tx.InsertIncidentWebhookReceiver(ctx, out); err != nil {
			return err
		}
		kind, id := incidentActor(a)
		return c.appendAudit(ctx, tx, application.AuditEvent{TenantID: a.TenantID, EntryType: "incident_webhook_receiver.created", SubjectType: "incident_webhook_receiver", SubjectID: out.ID, ActorType: kind, ActorID: id, OccurredAt: now})
	})
	if err != nil {
		return operationsdomain.IncidentWebhookReceiver{}, err
	}
	return out, nil
}
func webhookDigest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

type incidentWebhookPayload struct {
	EventType  string    `json:"event_type"`
	Summary    string    `json:"summary"`
	EvidenceID string    `json:"evidence_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

func parseIncidentWebhookPayload(body []byte) (incidentWebhookPayload, error) {
	var p incidentWebhookPayload
	limits := jsonbounds.DefaultLimits()
	limits.MaxStringBytes = IncidentWebhookBodyLimit
	if !utf8.Valid(body) || jsonbounds.Validate(body, limits) != nil {
		return p, ErrValidation
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return p, ErrValidation
	}
	for k, v := range fields {
		switch k {
		case "event_type", "summary", "evidence_id", "occurred_at":
		default:
			return p, ErrValidation
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return p, ErrValidation
		}
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return p, ErrValidation
	}
	p.EventType, p.Summary, p.EvidenceID = strings.TrimSpace(p.EventType), strings.TrimSpace(p.Summary), strings.TrimSpace(p.EvidenceID)
	if !validEnvironmentText(p.EventType, IncidentWebhookBodyLimit) || !validEnvironmentText(p.Summary, IncidentWebhookBodyLimit) || !incidentOptionalText(p.EvidenceID, 1024) || !p.OccurredAt.IsZero() && !incidentTime(p.OccurredAt) {
		return p, ErrValidation
	}
	return p, nil
}
func validateWebhookEvidence(ctx context.Context, tx IncidentWebhookTransaction, incident IncidentSubject, id string) error {
	if id == "" {
		return nil
	}
	v, err := tx.ReadIncidentSubject(ctx, incident.TenantID, "evidence", id)
	if err != nil {
		return err
	}
	// Receiver authority is incident-scoped, not a tenant-wide evidence grant.
	if !validIncidentSubject(v, incident.TenantID, "evidence", id) || v.Resources.ProductID != incident.Resources.ProductID || v.Resources.ReleaseID != "" && v.Resources.ReleaseID != incident.Resources.ReleaseID {
		return ErrNotFound
	}
	return nil
}
func validWebhookDigest(v string) bool {
	b, err := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
	return strings.HasPrefix(v, "sha256:") && err == nil && len(b) == sha256.Size && strings.ToLower(v) == v
}
func validateWebhookReplay(v operationsdomain.IncidentWebhookEvent, e operationsdomain.IncidentTimelineEvent, r operationsdomain.IncidentWebhookReceiver, eventID string) bool {
	if strings.TrimSpace(e.EventType) == "" || strings.TrimSpace(e.Summary) == "" {
		return false
	}
	return validIncidentID(v.ID) && v.TenantID == r.TenantID && v.ReceiverID == r.ID && v.IncidentID == r.IncidentID && v.Provider == r.Provider && v.EventID == eventID && v.Result == "accepted" && v.SchemaVersion == operationsdomain.IncidentWebhookEventVersion && incidentTime(v.CreatedAt) && validWebhookDigest(v.PayloadHash) && validWebhookDigest(v.SignatureHash) && validIncidentID(e.ID) && e.ID == v.TimelineEventID && e.TenantID == r.TenantID && e.IncidentID == r.IncidentID && validEnvironmentText(e.EventType, IncidentWebhookBodyLimit) && validEnvironmentText(e.Summary, IncidentWebhookBodyLimit) && incidentOptionalText(e.EvidenceID, 1024) && e.SchemaVersion == operationsdomain.IncidentTimelineSchemaVersion && incidentTime(e.CreatedAt) && incidentTime(e.OccurredAt)
}
func (c *IncidentWebhookCommands) HandleIncidentWebhook(ctx context.Context, in HandleIncidentWebhookInput) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	zeroRecord, zeroEvent := operationsdomain.IncidentWebhookEvent{}, operationsdomain.IncidentTimelineEvent{}
	if c == nil {
		return zeroRecord, zeroEvent, ErrValidation
	}
	if err := incidentContextError(ctx); err != nil {
		return zeroRecord, zeroEvent, err
	}
	if !validEnvironmentText(in.ReceiverID, 1024) || !validEnvironmentText(in.EventID, 1024) || !validEnvironmentText(in.Signature, 1024) || !incidentTime(in.Timestamp) || len(in.Body) == 0 || len(in.Body) > IncidentWebhookBodyLimit {
		return zeroRecord, zeroEvent, ErrValidation
	}
	in.ReceiverID, in.EventID, in.Signature = strings.TrimSpace(in.ReceiverID), strings.TrimSpace(in.EventID), strings.TrimSpace(in.Signature)
	if !validIncidentID(in.ReceiverID) || !validIncidentID(in.EventID) || strings.ContainsAny(in.EventID, "\r\n") || in.Signature == "" {
		return zeroRecord, zeroEvent, ErrValidation
	}
	in.Body = bytes.Clone(in.Body)
	now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !incidentTime(now) {
		return zeroRecord, zeroEvent, ErrValidation
	}
	if in.Timestamp.Before(now.Add(-IncidentWebhookTimestampTolerance)) || in.Timestamp.After(now.Add(IncidentWebhookTimestampTolerance)) {
		return zeroRecord, zeroEvent, application.ErrUnauthorized
	}
	signature, err := DecodeIncidentWebhookSignature(in.Signature)
	if err != nil {
		return zeroRecord, zeroEvent, err
	}
	tenant, err := c.config.Routing.LookupIncidentWebhookTenant(ctx, in.ReceiverID)
	if err != nil {
		return zeroRecord, zeroEvent, err
	}
	if !validIncidentID(tenant) {
		return zeroRecord, zeroEvent, ErrNotFound
	}
	if len(tenant)+len(in.ReceiverID)+len(in.EventID) > MaxIncidentWebhookReplayKeyBytes {
		return zeroRecord, zeroEvent, ErrValidation
	}
	var record operationsdomain.IncidentWebhookEvent
	var event operationsdomain.IncidentTimelineEvent
	err = c.execute(ctx, func(ctx context.Context, tx IncidentWebhookTransaction) error {
		r, err := tx.ReadIncidentWebhookReceiver(ctx, tenant, in.ReceiverID)
		if err != nil {
			return err
		}
		if r.ID != in.ReceiverID || r.TenantID != tenant || !validIncidentID(r.IncidentID) || r.Status != "active" || !validEnvironmentText(r.Provider, 65536) || strings.TrimSpace(r.Provider) == "" {
			return ErrNotFound
		}
		key, err := DecodeIncidentWebhookPublicKey(r.PublicKey)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(key), IncidentWebhookSignedPayload(in.Timestamp, in.EventID, in.Body), signature) {
			return application.ErrUnauthorized
		}
		incident, err := tx.ReadIncidentSubject(ctx, tenant, "incident", r.IncidentID)
		if err != nil {
			return err
		}
		if !validIncidentSubject(incident, tenant, "incident", r.IncidentID) {
			return ErrNotFound
		}
		old, timeline, err := tx.ReadIncidentWebhookReplay(ctx, tenant, r.ID, in.EventID)
		if err == nil {
			if old.PayloadHash != webhookDigest(in.Body) || !validateWebhookReplay(old, timeline, r, in.EventID) {
				return ErrConflict
			}
			if err := validateWebhookEvidence(ctx, tx, incident, timeline.EvidenceID); err != nil {
				return err
			}
			record, event = old, timeline
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		p, err := parseIncidentWebhookPayload(in.Body)
		if err != nil {
			return err
		}
		if err := validateWebhookEvidence(ctx, tx, incident, p.EvidenceID); err != nil {
			return err
		}
		if p.OccurredAt.IsZero() {
			p.OccurredAt = now
		}
		event = operationsdomain.IncidentTimelineEvent{ID: c.config.IDs.NewID("it"), TenantID: tenant, IncidentID: r.IncidentID, EventType: p.EventType, Summary: p.Summary, EvidenceID: p.EvidenceID, OccurredAt: p.OccurredAt.UTC().Truncate(time.Microsecond), SchemaVersion: operationsdomain.IncidentTimelineSchemaVersion, CreatedAt: now}
		record = operationsdomain.IncidentWebhookEvent{ID: c.config.IDs.NewID("iwe"), TenantID: tenant, ReceiverID: r.ID, IncidentID: r.IncidentID, Provider: r.Provider, EventID: in.EventID, PayloadHash: webhookDigest(in.Body), SignatureHash: webhookDigest(signature), TimelineEventID: event.ID, Result: "accepted", SchemaVersion: operationsdomain.IncidentWebhookEventVersion, CreatedAt: now}
		if !validIncidentID(record.ID) || !validIncidentID(event.ID) {
			return ErrValidation
		}
		if err := tx.InsertIncidentWebhookEvent(ctx, record, event); err != nil {
			return err
		}
		return c.appendAudit(ctx, tx, application.AuditEvent{TenantID: tenant, EntryType: "incident.webhook_timeline_recorded", SubjectType: "incident", SubjectID: r.IncidentID, ActorType: "webhook", ActorID: r.ID, PayloadHash: record.PayloadHash, OccurredAt: now})
	})
	if err != nil {
		return zeroRecord, zeroEvent, err
	}
	return record, event, nil
}
