package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func memoryIncidentWebhookFixture(t *testing.T) (*memoryUnitOfWork, operationsapp.IncidentWebhookRouting, operationsapp.IncidentWebhookReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	routing, ok := tx.Repositories().Risk.(operationsapp.IncidentWebhookRouting)
	if !ok {
		t.Fatal("memory risk lacks focused webhook routing")
	}
	reader, ok := tx.Repositories().Risk.(operationsapp.IncidentWebhookReader)
	if !ok {
		t.Fatal("memory risk lacks focused webhook authority/replay readers")
	}
	tx.state.IncidentWebhookReceivers["receiver"] = domain.IncidentWebhookReceiver{ID: "receiver", TenantID: "tenant", IncidentID: "incident", Name: strings.Repeat("unselected-name", 10000), Provider: "provider", PublicKey: "recorded-public-key", Status: "active", SchemaVersion: "unselected-version", CreatedAt: fixedNow()}
	tx.state.IncidentTimelineEvents["timeline"] = domain.IncidentTimelineEvent{ID: "timeline", TenantID: "tenant", IncidentID: "incident", EventType: "recorded", Summary: "Summary", EvidenceID: "evidence", OccurredAt: fixedNow(), SchemaVersion: operationsdomain.IncidentTimelineSchemaVersion, CreatedAt: fixedNow()}
	tx.state.IncidentWebhookEvents["receipt"] = domain.IncidentWebhookEvent{ID: "receipt", TenantID: "tenant", ReceiverID: "receiver", IncidentID: "incident", Provider: "provider", EventID: "event", PayloadHash: "sha256:" + strings.Repeat("a", 64), SignatureHash: "sha256:" + strings.Repeat("b", 64), TimelineEventID: "timeline", Result: "accepted", SchemaVersion: operationsdomain.IncidentWebhookEventVersion, CreatedAt: fixedNow()}
	return tx, routing, reader
}

func TestMemoryIncidentWebhookReadersSelectOnlyCurrentAuthorityAndBoundReplay(t *testing.T) {
	tx, routing, reader := memoryIncidentWebhookFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if tenant, err := routing.LookupIncidentWebhookTenant(t.Context(), "receiver"); err != nil || tenant != "tenant" {
		t.Fatal("locator lost current tenant", err)
	}
	v, err := reader.ReadIncidentWebhookReceiver(t.Context(), "tenant", "receiver")
	want := operationsdomain.IncidentWebhookReceiver{ID: "receiver", TenantID: "tenant", IncidentID: "incident", Provider: "provider", PublicKey: "recorded-public-key", Status: "active"}
	if err != nil || v != want {
		t.Fatal("authority read included descriptive metadata or lost public trust fields", err)
	}
	receipt, event, err := reader.ReadIncidentWebhookReplay(t.Context(), "tenant", "receiver", "event")
	if err != nil || receipt != operationsdomain.IncidentWebhookEvent(tx.state.IncidentWebhookEvents["receipt"]) || event != operationsdomain.IncidentTimelineEvent(tx.state.IncidentTimelineEvents["timeline"]) {
		t.Fatal("replay lost complete receipt/timeline", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("webhook readers changed snapshot")
	}
	if _, err := reader.ReadIncidentWebhookReceiver(t.Context(), "foreign", "receiver"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign receiver accepted", err)
	}
	if _, _, err := reader.ReadIncidentWebhookReplay(t.Context(), "foreign", "receiver", "event"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign replay accepted", err)
	}
	value := tx.state.IncidentWebhookReceivers["receiver"]
	value.Provider = strings.Repeat("p", 65536)
	tx.state.IncidentWebhookReceivers[value.ID] = value
	if v, err := reader.ReadIncidentWebhookReceiver(t.Context(), "tenant", "receiver"); err != nil || v.Provider != value.Provider {
		t.Fatal("exact-limit authority rejected or truncated", err)
	}
	value.Provider = strings.Repeat("p", 65537)
	tx.state.IncidentWebhookReceivers[value.ID] = value
	if v, err := reader.ReadIncidentWebhookReceiver(t.Context(), "tenant", "receiver"); !errors.Is(err, ErrValidation) || v != (operationsdomain.IncidentWebhookReceiver{}) {
		t.Fatal("oversized authority returned partial receiver", err)
	}
	bad := tx.state.IncidentWebhookEvents["receipt"]
	bad.PayloadHash = strings.Repeat("h", 72)
	tx.state.IncidentWebhookEvents[bad.ID] = bad
	if v, e, err := reader.ReadIncidentWebhookReplay(t.Context(), "tenant", "receiver", "event"); !errors.Is(err, ErrConflict) || v != (operationsdomain.IncidentWebhookEvent{}) || e != (operationsdomain.IncidentTimelineEvent{}) {
		t.Fatal("oversized replay returned partial records", err)
	}
}

func TestMemoryIncidentWebhookReplayRejectsBrokenTimelineAndAmbiguousKey(t *testing.T) {
	tx, _, reader := memoryIncidentWebhookFixture(t)
	timeline := tx.state.IncidentTimelineEvents["timeline"]
	delete(tx.state.IncidentTimelineEvents, "timeline")
	if _, _, err := reader.ReadIncidentWebhookReplay(t.Context(), "tenant", "receiver", "event"); !errors.Is(err, ErrConflict) {
		t.Fatal("missing replay timeline accepted", err)
	}
	tx.state.IncidentTimelineEvents[timeline.ID] = timeline
	duplicate := tx.state.IncidentWebhookEvents["receipt"]
	duplicate.ID = "other"
	tx.state.IncidentWebhookEvents[duplicate.ID] = duplicate
	if _, _, err := reader.ReadIncidentWebhookReplay(t.Context(), "tenant", "receiver", "event"); !errors.Is(err, ErrConflict) {
		t.Fatal("ambiguous replay key accepted", err)
	}
	var missingContext context.Context
	if _, err := reader.ReadIncidentWebhookReceiver(missingContext, "tenant", "receiver"); err == nil {
		t.Fatal("nil callback context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := reader.ReadIncidentWebhookReplay(ctx, "tenant", "receiver", "event"); !errors.Is(err, context.Canceled) {
		t.Fatal("replay cancellation lost", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadIncidentWebhookReceiver(t.Context(), "tenant", "receiver"); err == nil {
		t.Fatal("closed callback transaction accepted")
	}
}
