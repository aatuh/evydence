package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestSignedIncidentWebhookRouteAuthorizationMatrix(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedOperationsFixtureScope(t, ledger, "Owner"), seedOperationsFixtureScope(t, ledger, "Foreign")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	commands := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return now })}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	foreignPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	ownerReceiver, err := commands.CreateIncidentWebhookReceiver(t.Context(), owner.actor, operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: owner.incident.ID, Name: "Pager", Provider: "fixture", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	foreignReceiver, err := commands.CreateIncidentWebhookReceiver(t.Context(), foreign.actor, operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: foreign.incident.ID, Name: "Pager", Provider: "fixture", PublicKey: base64.RawStdEncoding.EncodeToString(foreignPrivate.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.incidentWebhookCommands = commands
	s.authn = &configuredAuthenticator{actor: domain.Actor{TenantID: owner.actor.TenantID, KeyID: "admin", Scopes: []string{"*", "admin", "incident:write"}}}
	request := func(receiver, event string, body []byte, at time.Time, signer ed25519.PrivateKey, want int) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/incident-webhooks/"+receiver, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer fixture-admin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Evydence-Webhook-Event-ID", event)
		r.Header.Set("X-Evydence-Webhook-Timestamp", at.Format(time.RFC3339))
		r.Header.Set("X-Evydence-Webhook-Signature", "ed25519="+base64.RawStdEncoding.EncodeToString(ed25519.Sign(signer, operationsapp.IncidentWebhookSignedPayload(at, event, body))))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("signed callback status=%d want=%d", w.Code, want)
		}
		if want != 201 && (strings.Contains(w.Body.String(), `"webhook_event"`) || strings.Contains(w.Body.String(), `"timeline_event"`) || strings.Contains(w.Body.String(), owner.evidence.ID) || strings.Contains(w.Body.String(), foreign.evidence.ID)) {
			t.Fatal("signed callback denial disclosed evidence or receipts")
		}
		return w.Body.String()
	}
	body, err := json.Marshal(map[string]any{"event_type": "contained", "summary": "Recorded", "evidence_id": owner.evidence.ID})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	one := request(ownerReceiver.ID, "provider-event", body, now, private, 201)
	if !strings.Contains(one, owner.incident.ID) || !strings.Contains(one, owner.evidence.ID) || strings.Contains(one, foreign.incident.ID) || strings.Contains(one, foreign.evidence.ID) {
		t.Fatal("verified receiver did not remain incident/tenant bound")
	}
	retry := request(ownerReceiver.ID, "provider-event", body, now.Add(time.Minute), private, 201)
	if retry != one {
		t.Fatal("freshly signed natural retry changed the original receipt")
	}
	committed, err := factory.Snapshot()
	if err != nil || len(committed.IncidentWebhookEvents) != len(before.IncidentWebhookEvents)+1 || len(committed.IncidentTimelineEvents) != len(before.IncidentTimelineEvents)+1 || len(committed.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(committed.AuditEntries[foreign.actor.TenantID], before.AuditEntries[foreign.actor.TenantID]) || !reflect.DeepEqual(committed.Idempotency, before.Idempotency) {
		t.Fatal("signed delivery/retry changed natural-key, atomic audit or tenant isolation", err)
	}
	request(ownerReceiver.ID, "bad-signature-before-parse", []byte("{"), now, foreignPrivate, 401)
	request(ownerReceiver.ID, "stale", body, now.Add(-5*time.Minute-time.Second), private, 401)
	request(ownerReceiver.ID, "future", body, now.Add(5*time.Minute+time.Second), private, 401)
	request("missing", "missing", body, now, private, 404)
	request(foreignReceiver.ID, "foreign-key", body, now, private, 401)
	request(foreignReceiver.ID, "foreign-evidence", body, now, foreignPrivate, 404)
	request(ownerReceiver.ID, "provider-event", []byte("{"), now, private, 409)
	foreignBody, err := json.Marshal(map[string]any{"event_type": "contained", "summary": "Recorded", "evidence_id": foreign.evidence.ID})
	if err != nil {
		t.Fatal(err)
	}
	request(ownerReceiver.ID, "wrong-evidence", foreignBody, now, private, 404)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(committed, after) {
		t.Fatal("rejected signed receiver authority changed durable fixture state", err)
	}
}
