package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentWebhookHTTPFake struct {
	guards, creates, deliveries int
	actor                       identitydomain.Actor
	receiver                    operationsapp.CreateIncidentWebhookReceiverInput
	input                       operationsapp.HandleIncidentWebhookInput
	err                         error
}

func (f *incidentWebhookHTTPFake) AuthorizeCreateIncidentWebhookReceiver(_ context.Context, a identitydomain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) error {
	f.guards++
	f.actor, f.receiver = a, in
	return f.err
}
func (f *incidentWebhookHTTPFake) CreateIncidentWebhookReceiver(_ context.Context, a identitydomain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error) {
	f.creates++
	f.actor, f.receiver = a, in
	return operationsdomain.IncidentWebhookReceiver{ID: "receiver", TenantID: a.TenantID, IncidentID: in.IncidentID, PublicKey: in.PublicKey}, f.err
}
func (f *incidentWebhookHTTPFake) HandleIncidentWebhook(_ context.Context, in operationsapp.HandleIncidentWebhookInput) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	f.deliveries++
	f.input = in
	return operationsdomain.IncidentWebhookEvent{ID: "webhook-event", ReceiverID: in.ReceiverID, EventID: in.EventID}, operationsdomain.IncidentTimelineEvent{ID: "timeline-event"}, f.err
}
func TestIncidentWebhookHTTPFocusedPortsPreserveProtocolAndSafeErrors(t *testing.T) {
	base, secret := testServer(t)
	f := &incidentWebhookHTTPFake{}
	executor := &decisionHTTPExecutorFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{IncidentWebhookCommands: f}); err == nil {
		t.Fatal("receiver creation retained Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{IncidentWebhookCommands: f, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"Pager","provider":"pager","public_key":"encoded-public-key"}`
	path := "/v1/incidents/incident/webhook-receivers"
	postRaw(t, s, "", path, "unauthorized", []byte(body), 401)
	for _, bad := range []string{"null", "[]", body + " {}", strings.Replace(body, `"name":"Pager"`, `"name":null`, 1), strings.Replace(body, `"provider":"pager"`, `"provider":null`, 1), strings.Replace(body, `"public_key":"encoded-public-key"`, `"public_key":null`, 1), strings.Replace(body, `"name":"Pager"`, `"name":"one","name":"two"`, 1)} {
		postRaw(t, s, secret, path, "bad", []byte(bad), 400)
	}
	if f.creates+f.guards != 0 {
		t.Fatal("invalid receiver envelope reached service")
	}
	out := postRaw(t, s, secret, path, "receiver", []byte(body), 201)
	if f.creates != 1 || f.guards != 1 || f.actor.KeyID == "" || f.receiver.IncidentID != "incident" || f.receiver.Name != "Pager" || f.receiver.Provider != "pager" || f.receiver.PublicKey != "encoded-public-key" || !strings.Contains(out, `"public_key":"encoded-public-key"`) {
		t.Fatal(f, out)
	}
	calls := executor.calls
	public := func(mutate func(*httptest.ResponseRecorder, *operationsapp.HandleIncidentWebhookInput), header string, duplicate bool, want int) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/incident-webhooks/receiver", strings.NewReader("{unparsed exact bytes"))
		r.Header.Set("X-Evydence-Webhook-Event-ID", "provider-event")
		r.Header.Set("X-Evydence-Webhook-Timestamp", "2026-10-03T12:20:30.123456+02:00")
		r.Header.Set("X-Evydence-Webhook-Signature", "ed25519=encoded-signature")
		if header != "" {
			if duplicate {
				r.Header.Add(header, r.Header.Get(header))
			} else {
				r.Header.Del(header)
			}
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), "private") {
			t.Fatal(w.Code, w.Body.String())
		}
		if mutate != nil {
			mutate(w, &f.input)
		}
		return w.Body.String()
	}
	public(func(w *httptest.ResponseRecorder, in *operationsapp.HandleIncidentWebhookInput) {
		if in.ReceiverID != "receiver" || in.EventID != "provider-event" || in.Signature != "ed25519=encoded-signature" || string(in.Body) != "{unparsed exact bytes" || !in.Timestamp.Equal(time.Date(2026, 10, 3, 10, 20, 30, 123456000, time.UTC)) || !strings.Contains(w.Body.String(), `"webhook_event"`) || !strings.Contains(w.Body.String(), `"timeline_event"`) {
			t.Fatal(in, w.Body.String())
		}
	}, "", false, 201)
	for _, header := range []string{"X-Evydence-Webhook-Event-ID", "X-Evydence-Webhook-Timestamp", "X-Evydence-Webhook-Signature"} {
		before := f.deliveries
		public(nil, header, false, 400)
		public(nil, header, true, 400)
		if f.deliveries != before {
			t.Fatal("ambiguous protocol header reached service")
		}
	}
	for _, ec := range []struct {
		err    error
		status int
	}{{operationsapp.ErrValidation, 400}, {operationsapp.ErrNotFound, 404}, {operationsapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private webhook database"), 500}} {
		f.err = ec.err
		public(nil, "", false, ec.status)
	}
	if executor.calls != calls || f.creates != 1 || f.guards != 1 {
		t.Fatal("public callback used bearer/HTTP idempotency command")
	}
}
