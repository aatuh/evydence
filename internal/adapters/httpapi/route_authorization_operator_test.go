package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// Memory repositories deliberately have no terminal-job lifecycle. This
// controlled queue-I/O seam does not manufacture authorization errors. The
// actual Operations query/command policy and durable receipt repositories run
// natively; SQL queue mutation/audit atomicity remains live-gate evidence.
type authorizationQueueIO struct {
	diagnosticsCalls, replayCalls int
	jobID, actorID                string
	at                            time.Time
}

func (q *authorizationQueueIO) OutboxDiagnostics(ctx context.Context) (app.OutboxDiagnostics, error) {
	if err := ctx.Err(); err != nil {
		return app.OutboxDiagnostics{}, err
	}
	q.diagnosticsCalls++
	return app.OutboxDiagnostics{PendingJobs: 2, RunningJobs: 1, TerminalJobs: 3, OldestPendingCreatedAt: q.at}, nil
}

func (q *authorizationQueueIO) ReplayTerminalJob(ctx context.Context, job, actor string) (app.OutboxReplay, error) {
	if err := ctx.Err(); err != nil {
		return app.OutboxReplay{}, err
	}
	q.replayCalls++
	q.jobID, q.actorID = job, actor
	return app.OutboxReplay{JobID: job, Status: "queued", ReplayedAt: q.at}, nil
}

func addNativeOperatorAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation, path, method string
		replay                  bool
	}{
		{"outboxOperatorDiagnostics", "/v1/admin/outbox", http.MethodGet, false},
		{"replayTerminalOutboxJob", "/v1/admin/outbox/controlled-terminal-job/replay", http.MethodPost, true},
	} {
		cases[tc.operation] = func(t *testing.T) {
			f := newNativeAuthorizationFixture(t)
			queue := &authorizationQueueIO{at: f.owner.release.CreatedAt}
			f.server.bindOperatorFixtureResources(operatorFixtureResources{operator: queue, now: func() time.Time { return queue.at }})
			before, err := f.factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			var body []byte
			if tc.replay {
				body = []byte(`{}`)
			}
			f.requestWithHeaders(t, tc.operation, tc.method, tc.path, domain.Actor{}, body, 401, map[string]string{"Authorization": ""})
			for _, actor := range []domain.Actor{f.owner.actor, f.foreign.actor, {TenantID: f.owner.actor.TenantID, UserID: "tenant-admin", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.owner.actor.TenantID, Scopes: []string{"*"}}}}} {
				out := f.request(t, tc.operation, tc.method, tc.path, actor, body, 403)
				if strings.Contains(out.Body.String(), `"data"`) {
					t.Fatal("tenant admin acquired global queue metadata")
				}
				after, err := f.factory.Snapshot()
				if err != nil || !reflect.DeepEqual(before, after) || queue.diagnosticsCalls != 0 || queue.replayCalls != 0 {
					t.Fatal("denied operator request accessed queue I/O or changed receipts", err)
				}
			}
			instance := nativeOperationPrincipal(t, tc.operation, f.owner.actor)
			out := f.request(t, tc.operation, tc.method, tc.path, instance, body, 200)
			var envelope struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			after, err := f.factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if tc.replay {
				var result app.OutboxReplay
				if err := json.Unmarshal(envelope.Data, &result); err != nil {
					t.Fatal(err)
				}
				if result.JobID != "controlled-terminal-job" || result.Status != "queued" || !result.ReplayedAt.Equal(queue.at) || queue.replayCalls != 1 || queue.diagnosticsCalls != 0 || queue.actorID != instance.KeyID || queue.jobID != result.JobID || len(after.Idempotency) != len(before.Idempotency)+1 {
					t.Fatal("native operator replay lost its bound actor, safe result or exact I/O/receipt effect")
				}
				for key, receipt := range after.Idempotency {
					if _, existed := before.Idempotency[key]; existed {
						continue
					}
					if key.TenantID != instance.TenantID || key.Method != tc.method || key.Path != tc.path || receipt.State != app.IdempotencyCompleted || receipt.Status != 200 || receipt.Response == nil {
						t.Fatal("operator replay receipt is not an owned completion")
					}
					delete(after.Idempotency, key)
				}
				if !reflect.DeepEqual(before, after) {
					t.Fatal("controlled queue contract replay changed unrelated repositories")
				}
				// Same-key replay must not requeue, while loss of current instance
				// authority must block even the previously completed receipt.
				saved, err := f.factory.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				repeated := f.request(t, tc.operation, tc.method, tc.path, instance, body, 200)
				if !bytes.Equal(out.Body.Bytes(), repeated.Body.Bytes()) || queue.replayCalls != 1 {
					t.Fatal("operator replay repeated I/O or changed its receipt")
				}
				f.request(t, tc.operation, tc.method, tc.path, f.owner.actor, body, 403)
				latest, err := f.factory.Snapshot()
				if err != nil || !reflect.DeepEqual(saved, latest) || queue.replayCalls != 1 {
					t.Fatal("revoked instance capability retrieved a completed replay", err)
				}
			} else {
				var result app.OutboxDiagnostics
				if err := json.Unmarshal(envelope.Data, &result); err != nil {
					t.Fatal(err)
				}
				if result.PendingJobs != 2 || result.RunningJobs != 1 || result.TerminalJobs != 3 || !result.OldestPendingCreatedAt.Equal(queue.at) || queue.diagnosticsCalls != 1 || queue.replayCalls != 0 || !reflect.DeepEqual(before, after) {
					t.Fatal("native operator diagnostics lost bounded counts or wrote state")
				}
			}
			for _, private := range []string{f.owner.actor.TenantID, f.foreign.actor.TenantID, f.owner.evidence.ID, "payload", "failure_detail", "error_detail"} {
				if strings.Contains(out.Body.String(), private) {
					t.Fatal("operator response disclosed queue internals", tc.operation)
				}
			}
		}
	}
}
