package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestDurableCommandExecutorRequiresFactoryAndBothCallbacks(t *testing.T) {
	if _, err := BuildDurableCommandExecutor(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
	executor, err := BuildDurableCommandExecutor(app.NewMemoryUnitOfWorkFactory())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		authorize func(context.Context) error
		run       func(context.Context) (int, any, error)
	}{
		{nil, func(context.Context) (int, any, error) {
			t.Fatal("missing authorization executed command")
			return 0, nil, nil
		}},
		{func(context.Context) error { t.Fatal("missing command began authorization"); return nil }, nil},
	} {
		status, response, err := executor.WithBody(t.Context(), domain.Actor{}, "POST", "/test", "key", nil, test.authorize, test.run)
		if !errors.Is(err, app.ErrValidation) || status != 0 || response != nil {
			t.Fatal("incomplete durable command exposed a result", status, response, err)
		}
	}
}

type streamedNestedTransactionRejector struct{}

func (streamedNestedTransactionRejector) BeginUnitOfWork(context.Context) (app.UnitOfWork, error) {
	return nil, errors.New("stream callback lost its active transaction")
}

func TestDurableStreamedCommandExecutorReauthorizesBeforeReplay(t *testing.T) {
	memory := app.NewMemoryUnitOfWorkFactory()
	if err := app.ExecuteUnitOfWork(t.Context(), memory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Stream", CreatedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)})
	}); err != nil {
		t.Fatal(err)
	}
	executor, err := BuildDurableCommandExecutor(memory)
	if err != nil {
		t.Fatal(err)
	}
	streamed, ok := executor.(httpapi.DurableStreamedCommandExecutor)
	if !ok {
		t.Fatal("durable executor cannot handle a bounded streamed source")
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key"}
	digest := app.BytesPayloadSource([]byte("document")).Digest
	authorizations, executions := 0, 0
	denied := false
	guard := func(ctx context.Context) error {
		authorizations++
		// A nested command must join the active transaction, not open a new one.
		if err := app.ExecuteUnitOfWork(ctx, streamedNestedTransactionRejector{}, func(context.Context, app.Repositories) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if denied {
			return app.ErrForbidden
		}
		return nil
	}
	run := func(ctx context.Context) (int, any, error) {
		executions++
		if err := app.ExecuteUnitOfWork(ctx, streamedNestedTransactionRejector{}, func(context.Context, app.Repositories) error { return nil }); err != nil {
			t.Fatal(err)
		}
		return 201, map[string]any{"id": "record"}, nil
	}
	for i := 0; i < 2; i++ {
		status, response, err := streamed.WithBodyDigest(t.Context(), a, "POST", "/stream", "key", digest, guard, run)
		v, ok := response.(map[string]any)
		if err != nil || status != 201 || !ok || v["id"] != "record" {
			t.Fatal("stream replay changed", status, response, err)
		}
	}
	denied = true
	status, response, err := streamed.WithBodyDigest(t.Context(), a, "POST", "/stream", "key", digest, guard, run)
	if !errors.Is(err, app.ErrForbidden) || status != 0 || response != nil || authorizations != 3 || executions != 1 {
		t.Fatal("revocation exposed replay", status, response, err, authorizations, executions)
	}
	for _, callbacks := range []struct {
		guard func(context.Context) error
		run   func(context.Context) (int, any, error)
	}{{nil, run}, {guard, nil}} {
		status, response, err := streamed.WithBodyDigest(t.Context(), a, "POST", "/stream", "missing", digest, callbacks.guard, callbacks.run)
		if !errors.Is(err, app.ErrValidation) || status != 0 || response != nil {
			t.Fatal("missing callback accepted", status, response, err)
		}
	}
	if _, _, err := streamed.WithBodyDigest(t.Context(), a, "POST", "/stream", "bad-digest", "invalid", guard, run); !errors.Is(err, app.ErrValidation) || authorizations != 3 || executions != 1 {
		t.Fatal("invalid digest reached callbacks", err, authorizations, executions)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Idempotency) != 1 {
		t.Fatal("failed validation or authorization reserved a record", snapshot, err)
	}
}
