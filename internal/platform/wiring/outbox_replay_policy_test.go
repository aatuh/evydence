package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestOutboxReplayPolicyRejectsTenantAuthorityBeforeSavedReplayAccess(t *testing.T) {
	// No executor or service is installed: reaching either on a denied call is
	// a failure, including when a matching idempotency response might exist.
	command := outboxReplayCommand{}
	for _, actor := range []domain.Actor{
		{TenantID: "tenant", KeyID: "key"},
		{TenantID: "tenant", UserID: "user", SessionID: "session"},
		{TenantID: "tenant", CollectorID: "collector", KeyID: "collector-key"},
	} {
		actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*", "instance:admin"}}}
		for _, scope := range []string{"admin", "*", "identity:admin"} {
			actor.Scopes = []string{scope}
			status, response, err := command.ReplayIdempotent(t.Context(), actor, "POST", "/admin/outbox/job/replay", "saved-replay", []byte(`{}`), "job")
			if status != 0 || response != nil || !errors.Is(err, app.ErrForbidden) {
				t.Fatalf("tenant authority reached replay: status=%d response=%v error=%v", status, response, err)
			}
		}
	}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"instance:admin"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	status, response, err := command.ReplayIdempotent(ctx, actor, "POST", "/admin/outbox/job/replay", "saved-replay", nil, "job")
	if status != 0 || response != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation reached replay: status=%d response=%v error=%v", status, response, err)
	}
}
