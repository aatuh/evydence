package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestIdempotencyCompletedReplayAuthorizationUsesOriginalSafeResponseAndTransaction(t *testing.T) {
	ctx := t.Context()
	memory := NewMemoryUnitOfWorkFactory()
	actor := domain.Actor{TenantID: "tenant", KeyID: "caller"}
	seedIdempotencyTenant(t, memory, actor.TenantID)
	runs, guards := 0, 0
	denied := false
	x := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow, AuthorizeReplay: func(ctx context.Context, repos Repositories, response any) error {
		guards++
		v, ok := response.(map[string]any)
		if !ok || v["id"] != "original" || v["secret"] != nil {
			t.Fatalf("replay guard received unsafe or regenerated result: %#v", response)
		}
		return ExecuteUnitOfWork(ctx, memory, func(_ context.Context, nested Repositories) error {
			if nested.Idempotency != repos.Idempotency {
				t.Fatal("replay guard opened another transaction")
			}
			if denied {
				return ErrForbidden
			}
			return nil
		})
	}}
	run := func(context.Context, Repositories) (int, any, error) {
		runs++
		return 201, map[string]any{"id": "original", "selected_ids": []string{"historical"}, "secret": "one-time-secret"}, nil
	}
	request := func(body string) (int, any, error) {
		return x.WithBody(ctx, actor, "POST", "/snapshot", "same", []byte(body), run)
	}
	if s, v, err := request(`{}`); err != nil || s != 201 || v.(map[string]any)["secret"] != "one-time-secret" || guards != 0 {
		t.Fatal("fresh execution changed", s, v, err, guards)
	}
	if s, _, err := request(`{}`); err != nil || s != 201 || guards != 1 || runs != 1 {
		t.Fatal("completed replay skipped guard or executed again", s, err, guards, runs)
	}
	denied = true
	if s, v, err := request(`{}`); !errors.Is(err, ErrForbidden) || s != 0 || v != nil {
		t.Fatal("denied historical selection leaked replay", s, v, err)
	}
	before := guards
	if _, _, err := request(`{} `); !errors.Is(err, ErrIdempotencyConflict) || guards != before {
		t.Fatal("changed intent reached completed-response authorization", err, guards, before)
	}
	denied = false
	if s, _, err := request(`{}`); err != nil || s != 201 || runs != 1 {
		t.Fatal("denial corrupted original completed replay", s, err, runs)
	}
	state, err := memory.Snapshot()
	if err != nil || len(state.Idempotency) != 1 {
		t.Fatal("replay guard wrote extra records", err, len(state.Idempotency))
	}
}
