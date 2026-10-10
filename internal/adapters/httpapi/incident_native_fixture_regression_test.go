package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestIncidentNativeFixtureUsesCurrentReferencesExplicitTimeAndAtomicAudit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("incident used aggregate clock") }})
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"incident:write"}}}}
	in := operationsapp.CreateIncidentInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID, Title: " Incident ", Severity: " HIGH "}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateIncident(t.Context(), human, in); err != nil || clock.calls != 0 {
		t.Fatal("incident guard used time/effects or lost current scope", err)
	}
	incident, err := f.CreateIncident(t.Context(), human, in)
	if err != nil || incident.ID == "" || incident.TenantID != human.TenantID || incident.ProductID != in.ProductID || incident.ReleaseID != in.ReleaseID || incident.Title != "Incident" || incident.Severity != "high" || incident.Status.String() != "open" || incident.OpenedAt != clock.at || incident.CreatedAt != clock.at || incident.ClosedAt != nil || incident.SchemaVersion != operationsdomain.IncidentSchemaVersion {
		t.Fatal("incident creation lost public fields/current references/time", err)
	}
	timelineIn := operationsapp.RecordIncidentTimelineInput{EventType: " noted ", Summary: " Recorded ", EvidenceID: owner.evidence.ID}
	if err := f.AuthorizeRecordIncidentTimelineEvent(t.Context(), human, incident.ID, timelineIn); err != nil {
		t.Fatal("new incident was not available to current timeline guard", err)
	}
	event, err := f.RecordIncidentTimelineEvent(t.Context(), human, incident.ID, timelineIn)
	if err != nil || event.ID == "" || event.TenantID != human.TenantID || event.IncidentID != incident.ID || event.EventType != "noted" || event.Summary != "Recorded" || event.EvidenceID != owner.evidence.ID || event.OccurredAt != clock.at || event.CreatedAt != clock.at || event.SchemaVersion != operationsdomain.IncidentTimelineSchemaVersion {
		t.Fatal("timeline lost complete DTO/current references", err)
	}
	due := clock.at.Add(time.Hour)
	taskIn := operationsapp.CreateRemediationTaskInput{IncidentID: incident.ID, ReleaseID: owner.release.ID, EvidenceID: owner.evidence.ID, Title: " Patch ", Owner: " Team ", DueAt: &due}
	if err := f.AuthorizeCreateRemediationTask(t.Context(), human, taskIn); err != nil {
		t.Fatal("task guard lost current independent references", err)
	}
	task, err := f.CreateRemediationTask(t.Context(), human, taskIn)
	if err != nil || task.ID == "" || task.TenantID != human.TenantID || task.IncidentID != incident.ID || task.ReleaseID != owner.release.ID || task.EvidenceID != owner.evidence.ID || task.Title != "Patch" || task.Owner != "Team" || task.Status != "open" || task.DueAt == nil || *task.DueAt != due || task.CreatedAt != clock.at || task.SchemaVersion != operationsdomain.RemediationTaskSchemaVersion || clock.calls != 3 {
		t.Fatal("task lost complete DTO/time", err)
	}
	*task.DueAt = task.DueAt.Add(time.Hour)
	after, err := base.Snapshot()
	if err != nil || len(after.Incidents) != len(before.Incidents)+1 || len(after.IncidentTimelineEvents) != len(before.IncidentTimelineEvents)+1 || len(after.RemediationTasks) != len(before.RemediationTasks)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+3 || *after.RemediationTasks[task.ID].DueAt != due {
		t.Fatal("incident effects were not atomic or result aliased stored task", err)
	}
	for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != human.UserID {
			t.Fatal("human incident audit attribution lost")
		}
	}
	factory.fail = true
	if v, err := f.CreateIncident(t.Context(), human, in); err == nil || !reflect.DeepEqual(v, operationsdomain.Incident{}) {
		t.Fatal("failed commit exposed incident", err)
	}
	if v, err := f.RecordIncidentTimelineEvent(t.Context(), human, incident.ID, timelineIn); err == nil || v != (operationsdomain.IncidentTimelineEvent{}) {
		t.Fatal("failed commit exposed timeline", err)
	}
	if v, err := f.CreateRemediationTask(t.Context(), human, taskIn); err == nil || !reflect.DeepEqual(v, operationsdomain.RemediationTask{}) {
		t.Fatal("failed commit exposed task", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed incident writes published state", err)
	}
}

func TestIncidentWebhookNativeFixtureVerifiesSignatureReplayAndCurrentEvidence(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("webhook used aggregate clock") }})}, clock: clock}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	in := operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: owner.incident.ID, Name: " Pager ", Provider: " fixture ", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	if err := f.AuthorizeCreateIncidentWebhookReceiver(t.Context(), owner.actor, in); err != nil || clock.calls != 0 {
		t.Fatal("receiver preflight read private metadata/time/effects", err)
	}
	receiver, err := f.CreateIncidentWebhookReceiver(t.Context(), owner.actor, in)
	if err != nil || receiver.ID == "" || receiver.IncidentID != in.IncidentID || receiver.TenantID != owner.actor.TenantID || receiver.Name != "Pager" || receiver.Provider != "fixture" || receiver.PublicKey != in.PublicKey || receiver.Status != "active" || receiver.SchemaVersion != operationsdomain.IncidentWebhookReceiverVersion || receiver.CreatedAt != clock.at {
		t.Fatal("receiver lost full DTO/current references/time", err)
	}
	makeInput := func(id string, body []byte) operationsapp.HandleIncidentWebhookInput {
		return operationsapp.HandleIncidentWebhookInput{ReceiverID: receiver.ID, EventID: id, Timestamp: clock.at, Body: body, Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, operationsapp.IncidentWebhookSignedPayload(clock.at, id, body)))}
	}
	body := []byte(fmt.Sprintf(`{"event_type":"contained","summary":"Recorded","evidence_id":%q}`, owner.evidence.ID))
	request := makeInput("event", body)
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	record, event, err := f.HandleIncidentWebhook(t.Context(), request)
	if err != nil || record.ID == "" || record.TenantID != receiver.TenantID || record.ReceiverID != receiver.ID || record.IncidentID != receiver.IncidentID || record.Provider != receiver.Provider || record.EventID != request.EventID || record.PayloadHash == "" || record.SignatureHash == "" || record.TimelineEventID != event.ID || record.Result != "accepted" || record.SchemaVersion != operationsdomain.IncidentWebhookEventVersion || event.EventType != "contained" || event.Summary != "Recorded" || event.EvidenceID != owner.evidence.ID || event.IncidentID != receiver.IncidentID || event.OccurredAt != clock.at || event.CreatedAt != clock.at {
		t.Fatal("signed callback lost record/timeline fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.IncidentWebhookEvents) != len(before.IncidentWebhookEvents)+1 || len(after.IncidentTimelineEvents) != len(before.IncidentTimelineEvents)+1 || len(after.AuditEntries[receiver.TenantID]) != len(before.AuditEntries[receiver.TenantID])+1 || !reflect.DeepEqual(before.Idempotency, after.Idempotency) {
		t.Fatal("business replay effects were not atomic/independent of HTTP replay", err)
	}
	if v, e, err := f.HandleIncidentWebhook(t.Context(), request); err != nil || v != record || e != event {
		t.Fatal("duplicate callback changed original receipt", err)
	}
	changed := makeInput("event", append(append([]byte(nil), body...), ' '))
	if _, _, err := f.HandleIncidentWebhook(t.Context(), changed); !errors.Is(err, app.ErrConflict) {
		t.Fatal("different signed bytes reused business key", err)
	}
	bad := makeInput("bad", []byte("not-json"))
	bad.Signature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, _, err := f.HandleIncidentWebhook(t.Context(), bad); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("unverified payload was parsed before signature", err)
	}
	if _, _, err := f.HandleIncidentWebhook(t.Context(), makeInput("malformed", []byte("not-json"))); !errors.Is(err, app.ErrValidation) {
		t.Fatal("authenticated malformed payload accepted", err)
	}
	foreignBody := []byte(fmt.Sprintf(`{"event_type":"noted","summary":"Foreign","evidence_id":%q}`, foreign.evidence.ID))
	if _, _, err := f.HandleIncidentWebhook(t.Context(), makeInput("foreign", foreignBody)); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("callback linked foreign evidence", err)
	}
	stale := request
	stale.Timestamp = clock.at.Add(-6 * time.Minute)
	if _, _, err := f.HandleIncidentWebhook(t.Context(), stale); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("stale callback accepted", err)
	}
	factory.fail = true
	if v, e, err := f.HandleIncidentWebhook(t.Context(), makeInput("failed", body)); err == nil || v != (operationsdomain.IncidentWebhookEvent{}) || e != (operationsdomain.IncidentTimelineEvent{}) {
		t.Fatal("failed callback transaction exposed partial receipt", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("duplicate/denied/failed callback changed state", err)
	}
}

func TestIncidentNativeFixtureRequiresRepositoriesAndRejectsForeignScopes(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: base})}}
	in := operationsapp.CreateIncidentInput{ProductID: foreign.product.ID, ReleaseID: foreign.release.ID, Title: "Incident", Severity: "high"}
	if _, err := f.CreateIncident(t.Context(), owner.actor, in); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign incident creation accepted", err)
	}
	if _, err := f.RecordIncidentTimelineEvent(t.Context(), owner.actor, foreign.incident.ID, operationsapp.RecordIncidentTimelineInput{EventType: "note", Summary: "Recorded"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign incident timeline accepted", err)
	}
	in.ProductID, in.ReleaseID = owner.product.ID, owner.release.ID
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"incident:write"}}
	if _, err := f.CreateIncident(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked incident grant accepted", err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range []operationsapp.CreateRemediationTaskInput{
		{IncidentID: foreign.incident.ID, Title: "Patch", Owner: "Team"},
		{ReleaseID: foreign.release.ID, Title: "Patch", Owner: "Team"},
		{IncidentID: owner.incident.ID, EvidenceID: foreign.evidence.ID, Title: "Patch", Owner: "Team"},
	} {
		if v, err := f.CreateRemediationTask(t.Context(), owner.actor, task); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, operationsdomain.RemediationTask{}) {
			t.Fatal("task accepted foreign reference or exposed a result", err)
		}
	}
	if v, err := f.RecordIncidentTimelineEvent(t.Context(), owner.actor, owner.incident.ID, operationsapp.RecordIncidentTimelineInput{EventType: "note", Summary: "Recorded", EvidenceID: foreign.evidence.ID}); !errors.Is(err, app.ErrNotFound) || v != (operationsdomain.IncidentTimelineEvent{}) {
		t.Fatal("timeline accepted foreign evidence or exposed a result", err)
	}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", 32)))
	receiverIn := operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: foreign.incident.ID, Name: "Pager", Provider: "fixture", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	if v, err := f.CreateIncidentWebhookReceiver(t.Context(), owner.actor, receiverIn); !errors.Is(err, app.ErrNotFound) || v != (operationsdomain.IncidentWebhookReceiver{}) {
		t.Fatal("receiver accepted foreign incident or exposed a result", err)
	}
	receiverIn.IncidentID = owner.incident.ID
	if v, err := f.CreateIncidentWebhookReceiver(t.Context(), human, receiverIn); !errors.Is(err, app.ErrForbidden) || v != (operationsdomain.IncidentWebhookReceiver{}) {
		t.Fatal("receiver accepted revoked grant or exposed a result", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied incident references changed state", err)
	}
	bare := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture"})}}
	if _, err := bare.CreateIncident(t.Context(), owner.actor, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored cached incident creation", err)
	}
	var missingContext context.Context
	if _, err := f.CreateIncident(missingContext, owner.actor, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil incident context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateIncident(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("incident cancellation lost", err)
	}
}
