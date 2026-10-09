package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type outboxDiagnosticsReaderFake struct {
	result OutboxCounts
	err    error
	reads  int
}

func (f *outboxDiagnosticsReaderFake) ReadOutboxCounts(context.Context) (OutboxCounts, error) {
	f.reads++
	return f.result, f.err
}

func TestOutboxDiagnosticsRequireExplicitInstanceAdminBeforeReading(t *testing.T) {
	reader := &outboxDiagnosticsReaderFake{result: OutboxCounts{
		PendingJobs: 2, RunningJobs: 1, TerminalJobs: 3,
		OldestPendingCreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}}
	service, err := NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{},
		{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}},
		{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"admin"}},
	} {
		_, err := service.Diagnostics(t.Context(), actor)
		if actor.TenantID == "" && !errors.Is(err, application.ErrUnauthorized) || actor.TenantID != "" && !errors.Is(err, application.ErrForbidden) || reader.reads != 0 {
			t.Fatalf("actor=%#v err=%v reads=%d", actor, err, reader.reads)
		}
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"instance:admin"}}
	result, err := service.Diagnostics(t.Context(), actor)
	if err != nil || result.PendingJobs != 2 || result.RunningJobs != 1 || result.TerminalJobs != 3 || reader.reads != 1 {
		t.Fatalf("diagnostics=%#v err=%v reads=%d", result, err, reader.reads)
	}
	reader.result.PendingJobs = -1
	if _, err := service.Diagnostics(t.Context(), actor); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("negative count error=%v", err)
	}
	reader.result.PendingJobs = 1
	reader.result.OldestPendingCreatedAt = time.Time{}
	if _, err := service.Diagnostics(t.Context(), actor); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("missing oldest pending time error=%v", err)
	}
}

func TestOutboxDiagnosticsRejectMissingReader(t *testing.T) {
	if _, err := NewOutboxDiagnostics(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
}
