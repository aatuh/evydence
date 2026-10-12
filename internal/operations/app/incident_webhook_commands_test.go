package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentWebhookFixture struct {
	incidentCommandFixture
	receiver operationsdomain.IncidentWebhookReceiver
	record   operationsdomain.IncidentWebhookEvent
	event    operationsdomain.IncidentTimelineEvent
	lookups  int
	onLookup func()
}

func (f *incidentWebhookFixture) LookupIncidentWebhookTenant(_ context.Context, id string) (string, error) {
	f.lookups++
	if f.onLookup != nil {
		f.onLookup()
	}
	if id != f.receiver.ID {
		return "", ErrNotFound
	}
	return f.receiver.TenantID, nil
}
func (f *incidentWebhookFixture) ExecuteIncidentWebhook(ctx context.Context, fn func(context.Context, IncidentWebhookTransaction) error) error {
	f.transactions++
	tx := *f
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if f.fail == "commit" {
		return ErrConflict
	}
	f.receiver, f.record, f.event, f.audits, f.reads = tx.receiver, tx.record, tx.event, tx.audits, tx.reads
	return nil
}
func (f *incidentWebhookFixture) ReadIncidentWebhookReceiver(_ context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	if f.fail == "receiver" {
		return operationsdomain.IncidentWebhookReceiver{}, ErrConflict
	}
	if tenant != f.receiver.TenantID || id != f.receiver.ID {
		return operationsdomain.IncidentWebhookReceiver{}, ErrNotFound
	}
	return f.receiver, nil
}
func (f *incidentWebhookFixture) ReadIncidentWebhookReplay(_ context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	if f.fail == "replay" {
		return operationsdomain.IncidentWebhookEvent{}, operationsdomain.IncidentTimelineEvent{}, ErrConflict
	}
	if f.record.ID == "" {
		return operationsdomain.IncidentWebhookEvent{}, operationsdomain.IncidentTimelineEvent{}, ErrNotFound
	}
	return f.record, f.event, nil
}
func (f *incidentWebhookFixture) InsertIncidentWebhookReceiver(_ context.Context, v operationsdomain.IncidentWebhookReceiver) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.receiver = v
	return nil
}
func (f *incidentWebhookFixture) InsertIncidentWebhookEvent(_ context.Context, v operationsdomain.IncidentWebhookEvent, e operationsdomain.IncidentTimelineEvent) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.record, f.event = v, e
	return nil
}
func webhookFixture(t *testing.T) (*IncidentWebhookCommands, *incidentWebhookFixture, identitydomain.Actor, ed25519.PrivateKey, time.Time) {
	t.Helper()
	_, incident, actor, now := incidentFixture(t)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	f := &incidentWebhookFixture{incidentCommandFixture: *incident, receiver: operationsdomain.IncidentWebhookReceiver{ID: "receiver", TenantID: "tenant", IncidentID: "incident", Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Status: "active", SchemaVersion: operationsdomain.IncidentWebhookReceiverVersion, CreatedAt: now}}
	c, err := NewIncidentWebhookCommands(IncidentWebhookCommandConfig{Transactions: f, Routing: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, actor, private, now
}
func signedWebhookInput(private ed25519.PrivateKey, at time.Time, body string) HandleIncidentWebhookInput {
	in := HandleIncidentWebhookInput{ReceiverID: "receiver", EventID: "provider-event", Timestamp: at, Body: []byte(body)}
	payload := append([]byte(at.UTC().Format(time.RFC3339)+"\nprovider-event\n"), in.Body...)
	in.Signature = "ed25519=" + base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return in
}
func TestIncidentWebhookCommandsCreateCurrentAuthorizedReceiverAtomically(t *testing.T) {
	c, f, actor, private, now := webhookFixture(t)
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"incident:write"}}}
	in := CreateIncidentWebhookReceiverInput{IncidentID: " incident ", Name: " Pager ", Provider: " pager ", PublicKey: " " + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) + " "}
	if err := c.AuthorizeCreateIncidentWebhookReceiver(t.Context(), actor, in); err != nil || len(f.audits) != 0 {
		t.Fatal("guard wrote or rejected release grant", err)
	}
	v, err := c.CreateIncidentWebhookReceiver(t.Context(), actor, in)
	if err != nil || v.ID != "iwr_new" || v.TenantID != "tenant" || v.IncidentID != "incident" || v.Name != "Pager" || v.Provider != "pager" || v.PublicKey != base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) || v.Status != "active" || v.CreatedAt != now || v.SchemaVersion != operationsdomain.IncidentWebhookReceiverVersion || len(f.audits) != 1 {
		t.Fatal(v, err)
	}
	audit := f.audits[0]
	if audit.EntryType != "incident_webhook_receiver.created" || audit.SubjectID != v.ID || audit.SubjectType != "incident_webhook_receiver" || audit.ActorID != "human" || audit.ActorType != "human_user" || audit.PayloadHash != "" || audit.TenantID != "tenant" || audit.OccurredAt != now {
		t.Fatal(audit)
	}
	for _, fail := range []string{"scope", "grant", "read", "insert", "audit", "commit"} {
		t.Run(fail, func(t *testing.T) {
			c, f, a, _, _ := webhookFixture(t)
			original := f.receiver
			f.fail = fail
			v, err := c.CreateIncidentWebhookReceiver(t.Context(), a, in)
			if err == nil || v.ID != "" || f.receiver != original || len(f.audits) != 0 {
				t.Fatal("receiver failure leaked", v, err)
			}
		})
	}
}
func TestIncidentWebhookCommandsVerifyBeforeParsingAndKeepNaturalReplay(t *testing.T) {
	c, f, _, private, now := webhookFixture(t)
	body := `{"event_type":" contained ","summary":" Containment ","evidence_id":"evidence"}`
	in := signedWebhookInput(private, now, body)
	v, event, err := c.HandleIncidentWebhook(t.Context(), in)
	signature, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(in.Signature, "ed25519="))
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if err != nil || v.ID != "iwe_new" || v.EventID != "provider-event" || v.Provider != "pager" || v.ReceiverID != "receiver" || v.IncidentID != "incident" || v.TenantID != "tenant" || v.Result != "accepted" || v.PayloadHash != fmt.Sprintf("sha256:%x", sha256.Sum256(in.Body)) || v.SignatureHash != fmt.Sprintf("sha256:%x", sha256.Sum256(signature)) || v.CreatedAt != now || v.TimelineEventID != event.ID || event.ID != "it_new" || event.IncidentID != "incident" || event.EventType != "contained" || event.Summary != "Containment" || event.EvidenceID != "evidence" || event.CreatedAt != now || event.OccurredAt != now || len(f.audits) != 1 {
		t.Fatal(v, event, err)
	}
	audit := f.audits[0]
	if audit.ActorType != "webhook" || audit.ActorID != "receiver" || audit.EntryType != "incident.webhook_timeline_recorded" || audit.SubjectType != "incident" || audit.SubjectID != "incident" || audit.PayloadHash != v.PayloadHash || audit.TenantID != "tenant" {
		t.Fatal(audit)
	}
	// A retry can be freshly signed; its original receipt must remain unchanged.
	retry := signedWebhookInput(private, now.Add(time.Minute), body)
	r, e, err := c.HandleIncidentWebhook(t.Context(), retry)
	if err != nil || r != v || e != event || len(f.audits) != 1 {
		t.Fatal("lost original retry result", r, e, err)
	}
	changed := signedWebhookInput(private, now, `{`)
	if _, _, err := c.HandleIncidentWebhook(t.Context(), changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed replay must conflict before parse", err)
	}
	subject := f.subjects["evidence:evidence"]
	subject.Resources.ProductID = "other"
	f.subjects["evidence:evidence"] = subject
	if _, _, err := c.HandleIncidentWebhook(t.Context(), retry); !errors.Is(err, ErrNotFound) || len(f.audits) != 1 {
		t.Fatal("replay trusted stale evidence", err)
	}
	for _, raw := range []string{`{`, `null`, `[]`, `{"event_type":"x","summary":"x"} {}`, `{"event_type":"x","summary":"x","unknown":1}`, `{"event_type":"x","event_type":"y","summary":"x"}`, `{"event_type":"x","summary":"x","evidence_id":null}`, `{"event_type":"x","summary":"x","occurred_at":null}`, `{"event_type":"x","summary":" "}`, "\xff"} {
		c, f, _, private, now := webhookFixture(t)
		in := signedWebhookInput(private, now, raw)
		in.Signature = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
		if _, _, err := c.HandleIncidentWebhook(t.Context(), in); !errors.Is(err, application.ErrUnauthorized) {
			t.Fatal("parsed unauthenticated body", raw, err)
		}
		in = signedWebhookInput(private, now, raw)
		if _, _, err := c.HandleIncidentWebhook(t.Context(), in); !errors.Is(err, ErrValidation) || f.record.ID != "" || len(f.audits) != 0 {
			t.Fatal(raw, err)
		}
	}
}
func TestIncidentWebhookCommandsRejectStaleAuthorityAndRollbackFailures(t *testing.T) {
	for _, fail := range []string{"receiver", "read", "replay", "insert", "audit", "commit"} {
		t.Run(fail, func(t *testing.T) {
			c, f, _, private, now := webhookFixture(t)
			f.fail = fail
			v, e, err := c.HandleIncidentWebhook(t.Context(), signedWebhookInput(private, now, `{"event_type":"x","summary":"x"}`))
			if err == nil || v.ID != "" || e.ID != "" || f.record.ID != "" || f.event.ID != "" || len(f.audits) != 0 {
				t.Fatal("event failure leaked", v, e, err)
			}
		})
	}
	for _, change := range []func(*incidentWebhookFixture){func(f *incidentWebhookFixture) { f.receiver.Status = "revoked" }, func(f *incidentWebhookFixture) { f.receiver.IncidentID = "missing" }, func(f *incidentWebhookFixture) { f.receiver.TenantID = "other" }, func(f *incidentWebhookFixture) {
		f.receiver.PublicKey = base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	}} {
		c, f, _, private, now := webhookFixture(t)
		change(f)
		if _, _, err := c.HandleIncidentWebhook(t.Context(), signedWebhookInput(private, now, `{"event_type":"x","summary":"x"}`)); err == nil || len(f.audits) != 0 {
			t.Fatal("stale authority trusted", err)
		}
	}
	for _, delta := range []time.Duration{-5 * time.Minute, 5 * time.Minute, -5*time.Minute - time.Nanosecond, 5*time.Minute + time.Nanosecond} {
		c, f, _, private, now := webhookFixture(t)
		_, _, err := c.HandleIncidentWebhook(t.Context(), signedWebhookInput(private, now.Add(delta), `{"event_type":"x","summary":"x"}`))
		if delta < -5*time.Minute || delta > 5*time.Minute {
			if !errors.Is(err, application.ErrUnauthorized) || f.lookups != 0 {
				t.Fatal(delta, err)
			}
		} else if err != nil {
			t.Fatal(delta, err)
		}
	}
	c, f, _, private, now := webhookFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := c.HandleIncidentWebhook(ctx, signedWebhookInput(private, now, `{}`)); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	for _, mutate := range []func(*HandleIncidentWebhookInput){func(in *HandleIncidentWebhookInput) { in.EventID = "one\ntwo" }, func(in *HandleIncidentWebhookInput) { in.ReceiverID = strings.Repeat("x", 1025) }, func(in *HandleIncidentWebhookInput) { in.Body = make([]byte, (2<<20)+1) }, func(in *HandleIncidentWebhookInput) { in.Body = nil }} {
		in := signedWebhookInput(private, now, `{}`)
		mutate(&in)
		if _, _, err := c.HandleIncidentWebhook(t.Context(), in); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	if _, err := NewIncidentWebhookCommands(IncidentWebhookCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.audits, []application.AuditEvent(nil)) {
		t.Fatal("invalid input wrote")
	}
}

func TestIncidentWebhookCommandsRejectForgedReplayWithoutEffects(t *testing.T) {
	for name, change := range map[string]func(*incidentWebhookFixture){
		"receipt-tenant":         func(f *incidentWebhookFixture) { f.record.TenantID = "other" },
		"receipt-receiver":       func(f *incidentWebhookFixture) { f.record.ReceiverID = "other" },
		"receipt-event":          func(f *incidentWebhookFixture) { f.record.EventID = "other" },
		"receipt-incident":       func(f *incidentWebhookFixture) { f.record.IncidentID = "other" },
		"receipt-signature-hash": func(f *incidentWebhookFixture) { f.record.SignatureHash = "bad" },
		"timeline-identity":      func(f *incidentWebhookFixture) { f.event.ID = "other" },
		"timeline-tenant":        func(f *incidentWebhookFixture) { f.event.TenantID = "other" },
		"timeline-incident":      func(f *incidentWebhookFixture) { f.event.IncidentID = "other" },
		"timeline-schema":        func(f *incidentWebhookFixture) { f.event.SchemaVersion = "unknown" },
		"timeline-empty-event":   func(f *incidentWebhookFixture) { f.event.EventType = " " },
		"timeline-empty-summary": func(f *incidentWebhookFixture) { f.event.Summary = " " },
	} {
		t.Run(name, func(t *testing.T) {
			c, f, _, private, now := webhookFixture(t)
			in := signedWebhookInput(private, now, `{"event_type":"noted","summary":"Noted"}`)
			if _, _, err := c.HandleIncidentWebhook(t.Context(), in); err != nil {
				t.Fatal(err)
			}
			change(f)
			v, e, err := c.HandleIncidentWebhook(t.Context(), in)
			if !errors.Is(err, ErrConflict) || v.ID != "" || e.ID != "" || len(f.audits) != 1 {
				t.Fatal("forged replay trusted", v, e, err)
			}
		})
	}
}
func TestIncidentWebhookProtocolPreservesEncodingFramingAndInputOwnership(t *testing.T) {
	c, f, a, private, now := webhookFixture(t)
	public := private.Public().(ed25519.PublicKey)
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding} {
		key, err := DecodeIncidentWebhookPublicKey(" " + encoding.EncodeToString(public) + " ")
		if err != nil || !reflect.DeepEqual(key, []byte(public)) {
			t.Fatal("public key encoding changed", err)
		}
		body := []byte(" exact\nbody\r\n")
		at := now.In(time.FixedZone("offset", -2*3600))
		want := append([]byte(now.UTC().Format(time.RFC3339)+"\nevent\n"), body...)
		if actual := IncidentWebhookSignedPayload(at, " event ", body); !reflect.DeepEqual(actual, want) {
			t.Fatal("framing changed", actual, want)
		}
		signature := ed25519.Sign(private, want)
		for _, prefix := range []string{"", "ed25519="} {
			decoded, err := DecodeIncidentWebhookSignature(prefix + encoding.EncodeToString(signature))
			if err != nil || !reflect.DeepEqual(decoded, signature) {
				t.Fatal("signature encoding changed", err)
			}
		}
	}
	encodedKey := base64.RawStdEncoding.EncodeToString(public)
	for _, bad := range []string{"", strings.Repeat("x", 1025), base64.RawStdEncoding.EncodeToString(make([]byte, 31)), "bad\x00", encodedKey[:16] + "\n" + encodedKey[16:]} {
		if _, err := DecodeIncidentWebhookPublicKey(bad); !errors.Is(err, ErrValidation) {
			t.Fatal("bad public key", err)
		}
		if _, err := DecodeIncidentWebhookSignature(bad); !errors.Is(err, application.ErrUnauthorized) {
			t.Fatal("bad signature", err)
		}
	}
	encodedSignature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte("body")))
	if _, err := DecodeIncidentWebhookSignature(encodedSignature[:16] + "\n" + encodedSignature[16:]); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("ambiguous signature encoding accepted", err)
	}
	in := signedWebhookInput(private, now, `{"event_type":"noted","summary":"Noted"}`)
	originalBody := string(in.Body)
	f.onLookup = func() {
		for i := range in.Body {
			in.Body[i] = 'x'
		}
	}
	v, e, err := c.HandleIncidentWebhook(t.Context(), in)
	if err != nil || e.Summary != "Noted" || v.PayloadHash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(originalBody))) {
		t.Fatal("port mutated verified bytes", v, e, err)
	}
	for _, mutate := range []func(*CreateIncidentWebhookReceiverInput){func(in *CreateIncidentWebhookReceiverInput) { in.IncidentID = "" }, func(in *CreateIncidentWebhookReceiverInput) { in.Name = " " }, func(in *CreateIncidentWebhookReceiverInput) { in.Provider = "bad\x00" }, func(in *CreateIncidentWebhookReceiverInput) { in.Name = strings.Repeat("x", 65537) }, func(in *CreateIncidentWebhookReceiverInput) { in.PublicKey = "bad" }} {
		in := CreateIncidentWebhookReceiverInput{IncidentID: "incident", Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(public)}
		mutate(&in)
		before := f.transactions
		if _, err := c.CreateIncidentWebhookReceiver(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != before {
			t.Fatal("bad receiver reached storage", err)
		}
	}
	var missingContext context.Context
	if _, _, err := c.HandleIncidentWebhook(missingContext, in); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	c, f, _, private, now = webhookFixture(t)
	f.receiver.ID, f.receiver.TenantID = strings.Repeat("r", 1024), strings.Repeat("t", 1024)
	in = signedWebhookInput(private, now, `{}`)
	in.ReceiverID = f.receiver.ID
	in.EventID = strings.Repeat("e", 257)
	if _, _, err := c.HandleIncidentWebhook(t.Context(), in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
		t.Fatal("oversized replay tuple reached transaction", err)
	}
}
