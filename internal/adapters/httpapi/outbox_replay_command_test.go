package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type outboxReplayCommandFake struct {
	actor  domain.Actor
	jobID  string
	key    string
	method string
	path   string
	body   string
}

func (f *outboxReplayCommandFake) ReplayIdempotent(_ context.Context, actor domain.Actor, method, path, key string, body []byte, jobID string) (int, any, error) {
	f.actor, f.method, f.path, f.key, f.body, f.jobID = actor, method, path, key, string(body), jobID
	return http.StatusOK, map[string]any{
		"job_id": jobID, "status": "queued", "replayed_at": time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}, nil
}

func TestOutboxReplayHandlerUsesFocusedIdempotentCommandWithoutLedgerOperator(t *testing.T) {
	server, secret := testServer(t)
	command := &outboxReplayCommandFake{}
	server.outboxReplayCommand = command
	path := "/v1/admin/outbox/job_database_only/replay"
	body := postJSON(t, server, secret, path, "replay-database", map[string]any{}, http.StatusOK)
	if command.jobID != "job_database_only" || command.actor.KeyID == "" || command.key != "replay-database" || command.method != http.MethodPost || command.path != path || command.body != "{}" {
		t.Fatalf("focused replay command not called with authenticated request: %#v", command)
	}
	if !strings.Contains(body, `"job_id":"job_database_only"`) || strings.Contains(body, "payload") || strings.Contains(body, "failure_detail") {
		t.Fatalf("replay response disclosed unexpected fields: %s", body)
	}
}
