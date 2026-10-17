package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestOwnedResourcesNestedCleanupSharesParentDeadline(t *testing.T) {
	var outer, inner OwnedResources
	var deadline time.Time
	outer.Add("first", func(ctx context.Context) error { deadline, _ = ctx.Deadline(); return nil })
	inner.Add("provider", func(ctx context.Context) error {
		got, ok := ctx.Deadline()
		if !ok || !deadline.Equal(got) {
			t.Error("nested cleanup reset its budget")
		}
		return nil
	})
	outer.Add("providers", inner.CloseWithin)
	if err := outer.Close(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedResourcesNestedCleanupCannotOutliveExpiredBudget(t *testing.T) {
	var inner OwnedResources
	inner.Add("provider", func(context.Context) error { t.Error("started cleanup after deadline"); return nil })
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if err := inner.CloseWithin(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired parent budget ignored", err)
	}
	if err := inner.CloseWithin(t.Context()); err == nil {
		t.Fatal("unbounded parent cleanup context accepted")
	}
}

func TestCleanupTimeoutConfigurationRejectsUnsafeValues(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    time.Duration
		invalid bool
	}{
		{"", 5 * time.Second, false}, {" 1 ", time.Second, false}, {"60", time.Minute, false},
		{"0", 0, true}, {"-1", 0, true}, {"61", 0, true}, {"1s", 0, true}, {"private-secret-value", 0, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			environment, err := config.Capture([]string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=fixture", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=" + tc.value})
			if err != nil {
				t.Fatal(err)
			}
			settings, err := config.Parse(environment, config.Worker)
			got := settings.Runtime().ShutdownCleanupTimeout
			if got != tc.want || (err != nil) != tc.invalid {
				t.Fatal("invalid cleanup timeout contract", got, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-secret-value") {
				t.Fatal("invalid value leaked in config error")
			}
		})
	}
}
