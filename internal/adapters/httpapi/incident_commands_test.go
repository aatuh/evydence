package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentHTTPFake struct {
	guards, calls    int
	id               string
	actor            identitydomain.Actor
	incident         operationsapp.CreateIncidentInput
	timeline         operationsapp.RecordIncidentTimelineInput
	task             operationsapp.CreateRemediationTaskInput
	guardErr, runErr error
}

func (f *incidentHTTPFake) AuthorizeCreateIncident(_ context.Context, a identitydomain.Actor, in operationsapp.CreateIncidentInput) error {
	f.guards++
	f.actor, f.incident = a, in
	return f.guardErr
}
func (f *incidentHTTPFake) AuthorizeRecordIncidentTimelineEvent(_ context.Context, a identitydomain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) error {
	f.guards++
	f.actor, f.id, f.timeline = a, id, in
	return f.guardErr
}
func (f *incidentHTTPFake) AuthorizeCreateRemediationTask(_ context.Context, a identitydomain.Actor, in operationsapp.CreateRemediationTaskInput) error {
	f.guards++
	f.actor, f.task = a, in
	return f.guardErr
}
func (f *incidentHTTPFake) CreateIncident(_ context.Context, a identitydomain.Actor, in operationsapp.CreateIncidentInput) (operationsdomain.Incident, error) {
	f.calls++
	f.actor, f.incident = a, in
	status, _ := operationsdomain.ParseIncidentStatus("open")
	return operationsdomain.Incident{ID: "incident", TenantID: a.TenantID, Title: in.Title, Status: status}, f.runErr
}
func (f *incidentHTTPFake) RecordIncidentTimelineEvent(_ context.Context, a identitydomain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error) {
	f.calls++
	f.actor, f.id, f.timeline = a, id, in
	return operationsdomain.IncidentTimelineEvent{ID: "event", TenantID: a.TenantID, IncidentID: id}, f.runErr
}
func (f *incidentHTTPFake) CreateRemediationTask(_ context.Context, a identitydomain.Actor, in operationsapp.CreateRemediationTaskInput) (operationsdomain.RemediationTask, error) {
	f.calls++
	f.actor, f.task = a, in
	return operationsdomain.RemediationTask{ID: "task", TenantID: a.TenantID, Title: in.Title, Owner: in.Owner, DueAt: in.DueAt}, f.runErr
}

func TestIncidentHTTPFocusedCommandsPreserveDTOsAndRejectInvalidEnvelopes(t *testing.T) {
	base, secret := testServer(t)
	f := &incidentHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{IncidentCommands: f}); err == nil {
		t.Fatal("focused incidents retained Ledger idempotency")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{IncidentCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body string }{
		{"/v1/incidents", `{"product_id":"product","release_id":"release","title":"Incident","severity":"HIGH","opened_at":"2026-10-03T10:20:30Z"}`},
		{"/v1/incidents/incident/timeline", `{"event_type":"noted","summary":"Containment","evidence_id":"evidence","occurred_at":"2026-10-03T10:20:30Z"}`},
		{"/v1/remediation-tasks", `{"incident_id":"incident","release_id":"release","title":"Fix","owner":"Team","evidence_id":"evidence","due_at":"2026-10-03T10:20:30Z"}`},
	} {
		before := f.calls + f.guards
		postRaw(t, s, "", tc.path, "unauth", []byte(tc.body), 401)
		for i, bad := range []string{"null", "[]", tc.body + " {}", strings.Replace(tc.body, "{", `{"unknown":true,`, 1), strings.Replace(tc.body, "{", `{"title":"duplicate","title":"duplicate",`, 1), strings.Repeat(" ", 65537) + tc.body} {
			postRaw(t, s, secret, tc.path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(tc.body), &fields); err != nil {
			t.Fatal(err)
		}
		for field := range fields {
			var invalid map[string]any
			if err := json.Unmarshal([]byte(tc.body), &invalid); err != nil {
				t.Fatal(err)
			}
			invalid[field] = nil
			body, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			postRaw(t, s, secret, tc.path, "null-"+field, body, 400)
		}
		if f.calls+f.guards != before {
			t.Fatal("bad input reached focused command")
		}
		out := postRaw(t, s, secret, tc.path, "valid", []byte(tc.body), 201)
		if f.calls+f.guards != before+2 || f.actor.TenantID == "" || f.actor.KeyID == "" || !strings.Contains(out, `"id"`) {
			t.Fatal("lost actor/result", out)
		}
		at := time.Date(2026, 10, 3, 10, 20, 30, 0, time.UTC)
		switch tc.path {
		case "/v1/incidents":
			if f.incident.ProductID != "product" || f.incident.ReleaseID != "release" || f.incident.Title != "Incident" || f.incident.Severity != "HIGH" || !f.incident.OpenedAt.Equal(at) || !strings.Contains(out, `"status":"open"`) {
				t.Fatal(f.incident, out)
			}
		case "/v1/incidents/incident/timeline":
			if f.id != "incident" || f.timeline.EventType != "noted" || f.timeline.Summary != "Containment" || f.timeline.EvidenceID != "evidence" || !f.timeline.OccurredAt.Equal(at) {
				t.Fatal(f.timeline)
			}
		case "/v1/remediation-tasks":
			if f.task.IncidentID != "incident" || f.task.ReleaseID != "release" || f.task.Title != "Fix" || f.task.Owner != "Team" || f.task.EvidenceID != "evidence" || f.task.DueAt == nil || !f.task.DueAt.Equal(at) || !strings.Contains(out, `"due_at":"2026-10-03T10:20:30Z"`) {
				t.Fatal(f.task, out)
			}
		}
		for i, ec := range []struct {
			err  error
			code int
		}{{operationsapp.ErrValidation, 400}, {operationsapp.ErrNotFound, 404}, {operationsapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private incident SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if phase == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				calls := f.calls
				out := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), []byte(tc.body), ec.code)
				if strings.Contains(out, "private") || phase == "guard" && f.calls != calls {
					t.Fatal("unsafe denial", out)
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
	}
}
