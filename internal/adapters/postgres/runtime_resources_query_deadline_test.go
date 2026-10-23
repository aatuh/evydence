package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestRuntimeResourcesBoundsBlockedSQLAndRecovers(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	blocked, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := blocked.Exec(t.Context(), `LOCK TABLE outbox_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := s.ReadRuntimeResources(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) || result != (telemetry.RuntimeResources{}) || time.Since(started) > 3*time.Second {
		t.Fatal("blocked SQL exceeded the snapshot deadline or returned partial data", err)
	}
	if err := blocked.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRuntimeResources(t.Context()); err != nil {
		t.Fatal("resource query did not recover after lock release", err)
	}
}
