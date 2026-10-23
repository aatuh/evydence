package health

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestMonitorSeparatesInitializationDependenciesAndDrainFromLiveness(t *testing.T) {
	var calls atomic.Int32
	var outage atomic.Bool
	outage.Store(true)
	monitor, err := New([]Check{
		{Name: "migrations", Startup: true, Check: func(context.Context) error { calls.Add(1); return nil }},
		{Name: "object_store", Check: func(context.Context) error {
			calls.Add(1)
			if outage.Load() {
				return errors.New("https://CANARY_SECRET@provider.internal/private")
			}
			return nil
		}},
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !monitor.Live() || calls.Load() != 0 {
		t.Fatal("liveness consulted a dependency")
	}
	before, err := monitor.Snapshot(t.Context())
	if err != nil || before.StartupReady || before.Ready || calls.Load() != 0 {
		t.Fatal("uninitialized process served work or probed dependencies", before, err)
	}
	monitor.MarkInitialized()
	status, err := monitor.Snapshot(t.Context())
	if err != nil || !status.StartupReady || status.Ready || !monitor.Live() || calls.Load() != 2 {
		t.Fatal("object outage changed startup/liveness or failed to block readiness", status, err)
	}
	encoded, err := json.Marshal(status)
	if err != nil || strings.Contains(string(encoded), "CANARY") || strings.Contains(string(encoded), "provider.internal") {
		t.Fatal("dependency error escaped the typed snapshot", err)
	}
	monitor.MarkDraining()
	after, err := monitor.Snapshot(t.Context())
	if err != nil || after.Ready || !after.Draining || !monitor.Live() || calls.Load() != 2 {
		t.Fatal("drain did not block work without changing liveness", after, err)
	}
}

func TestMonitorPendingMigrationsBlockStartupAndReadiness(t *testing.T) {
	monitor, err := New([]Check{{Name: "migrations", Startup: true, Check: func(context.Context) error { return errors.New("pending migration CANARY_PRIVATE_PATH") }}}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	status, err := monitor.Snapshot(t.Context())
	if err != nil || status.StartupReady || status.Ready || !monitor.Live() {
		t.Fatal("pending migration admitted startup or work", status, err)
	}
}

func TestMonitorCachesFailuresAndRecoversWithoutExposingMutableCache(t *testing.T) {
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var failure atomic.Bool
	var calls atomic.Int32
	failure.Store(true)
	monitor, err := New([]Check{{Name: "postgres", Startup: true, Check: func(context.Context) error {
		calls.Add(1)
		if failure.Load() {
			return errors.New("CANARY_DATABASE_URL")
		}
		return nil
	}}}, Config{CacheTTL: time.Second, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	failed, err := monitor.Snapshot(t.Context())
	if err != nil || failed.Ready || len(failed.Checks) != 1 || failed.Checks[0].Status != Unavailable {
		t.Fatal("dependency failure did not block work", failed, err)
	}
	failure.Store(false)
	cached, err := monitor.Snapshot(t.Context())
	if err != nil || cached.Ready || calls.Load() != 1 {
		t.Fatal("failed snapshots did not prevent repeated dependency work", cached, err)
	}
	at = at.Add(time.Second + time.Nanosecond)
	recovered, err := monitor.Snapshot(t.Context())
	if err != nil || !recovered.Ready || !recovered.StartupReady || calls.Load() != 2 || recovered.Checks[0].Status != OK {
		t.Fatal("restored dependency failed to recover after cache expiry", recovered, err)
	}
	recovered.Checks[0].Status = Unavailable
	if again, err := monitor.Snapshot(t.Context()); err != nil || !again.Ready || again.Checks[0].Status != OK || calls.Load() != 2 {
		t.Fatal("caller mutation poisoned cached health", again, err)
	}
	at = at.Add(-time.Hour)
	if _, err := monitor.Snapshot(t.Context()); err != nil || calls.Load() != 3 {
		t.Fatal("backward wall clock extended a cached snapshot", err)
	}
}

func TestMonitorCoalescesConcurrentRefreshes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		started, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		monitor, err := New([]Check{{Name: "postgres", Check: func(ctx context.Context) error {
			if calls.Add(1) == 1 {
				close(started)
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}}, Config{})
		if err != nil {
			t.Fatal(err)
		}
		monitor.MarkInitialized()
		var group sync.WaitGroup
		failures := make(chan error, 32)
		for range 32 {
			group.Go(func() {
				status, err := monitor.Snapshot(ctx)
				if err != nil {
					failures <- err
				} else if !status.Ready {
					failures <- errors.New("coalesced refresh returned unavailable")
				}
			})
		}
		select {
		case <-started:
		case <-ctx.Done():
			group.Wait()
			t.Fatal("dependency refresh never started")
		}
		// All 32 requests are now blocked inside the monitor or its dependency.
		synctest.Wait()
		close(release)
		group.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
		if calls.Load() != 1 {
			t.Fatal("concurrent probes started repeated dependency refreshes", calls.Load())
		}
	})
}
func TestMonitorDoesNotCacheRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	monitor, err := New([]Check{{Name: "postgres", Check: func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	owner, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := monitor.Snapshot(owner); finished <- err }()
	<-started
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal("refresh ignored owner cancellation", err)
	}
	if recovered, err := monitor.Snapshot(t.Context()); err != nil || !recovered.Ready || calls.Load() != 2 {
		t.Fatal("cancelled owner poisoned the next independent request", recovered, err)
	}
	var absent context.Context
	if _, err := monitor.Snapshot(absent); err == nil {
		t.Fatal("nil probe context accepted")
	}
}

func TestMonitorBoundsDependencyAndTotalRefreshWork(t *testing.T) {
	var laterCalls atomic.Int32
	monitor, err := New([]Check{
		{Name: "postgres", Startup: true, Check: func(ctx context.Context) error { <-ctx.Done(); return nil }},
		{Name: "object_store", Check: func(context.Context) error { laterCalls.Add(1); return nil }},
	}, Config{CheckTimeout: time.Second, RefreshTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	status, err := monitor.Snapshot(t.Context())
	if err != nil || status.Ready || status.StartupReady || len(status.Checks) != 2 || laterCalls.Load() != 0 {
		t.Fatal("refresh budget did not bound work and fail closed", status, err)
	}
	for _, result := range status.Checks {
		if result.Status != Unavailable {
			t.Fatal("ignored deadline or unevaluated dependency was reported healthy", result)
		}
	}
}

func TestMonitorRejectsInvalidConfigurationAndChecks(t *testing.T) {
	probe := func(context.Context) error { return nil }
	for _, config := range []Config{{CacheTTL: -time.Second}, {CacheTTL: time.Minute}, {CheckTimeout: -time.Second}, {RefreshTimeout: -time.Second}} {
		if _, err := New(nil, config); err == nil {
			t.Fatal("invalid health timing accepted", config)
		}
	}
	for _, checks := range [][]Check{
		{{Name: "postgres"}},
		{{Name: "", Check: probe}},
		{{Name: "postgres://CANARY_SECRET", Check: probe}},
		{{Name: "postgres", Check: probe}, {Name: "postgres", Check: probe}},
	} {
		if _, err := New(checks, Config{}); err == nil {
			t.Fatal("invalid or duplicate dependency accepted")
		}
	}
}

func TestMonitorPanicBecomesUnavailableWithoutWedgeOrPrivateOutput(t *testing.T) {
	var calls atomic.Int32
	monitor, err := New([]Check{{Name: "signer", Check: func(context.Context) error {
		calls.Add(1)
		panic("CANARY_PRIVATE_PROVIDER_RESPONSE")
	}}}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	for range 2 {
		status, err := monitor.Snapshot(t.Context())
		if err != nil || status.Ready {
			t.Fatal("panicking dependency appeared healthy", status, err)
		}
		encoded, err := json.Marshal(status)
		if err != nil || strings.Contains(string(encoded), "CANARY") {
			t.Fatal("panic leaked into health output", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("panicking dependency bypassed failure cache", calls.Load())
	}
}

func TestMonitorDependencyDeadlineLeavesBudgetForLaterChecks(t *testing.T) {
	var laterCalls atomic.Int32
	monitor, err := New([]Check{
		{Name: "postgres", Check: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 10*time.Millisecond {
				t.Error("dependency did not receive the configured short deadline")
			}
			<-ctx.Done()
			return ctx.Err()
		}},
		{Name: "object_store", Check: func(context.Context) error { laterCalls.Add(1); return nil }},
	}, Config{CheckTimeout: 10 * time.Millisecond, RefreshTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	status, err := monitor.Snapshot(t.Context())
	if err != nil || status.Ready || laterCalls.Load() != 1 || len(status.Checks) != 2 || status.Checks[0].Status != Unavailable || status.Checks[1].Status != OK {
		t.Fatal("one unavailable dependency exhausted another dependency's budget", status, err)
	}
}

func TestMonitorWaiterCancellationDoesNotCancelRefreshOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		started, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		monitor, err := New([]Check{{Name: "postgres", Check: func(ctx context.Context) error {
			calls.Add(1)
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}}, Config{})
		if err != nil {
			t.Fatal(err)
		}
		monitor.MarkInitialized()
		ownerResult := make(chan error, 1)
		go func() {
			status, err := monitor.Snapshot(ctx)
			if err == nil && !status.Ready {
				err = errors.New("owner lost healthy refresh")
			}
			ownerResult <- err
		}()
		select {
		case <-started:
		case err := <-ownerResult:
			t.Fatal("owner never started a dependency check", err)
		case <-ctx.Done():
			ownerErr := <-ownerResult
			t.Fatal("owner never started a dependency check", ctx.Err(), ownerErr)
		}
		waiter, stopWaiter := context.WithCancel(ctx)
		waiterResult := make(chan error, 1)
		go func() { _, err := monitor.Snapshot(waiter); waiterResult <- err }()
		// The waiter must have joined the still-blocked owner before cancellation.
		synctest.Wait()
		stopWaiter()
		waiterErr := <-waiterResult
		close(release)
		ownerErr := <-ownerResult
		if !errors.Is(waiterErr, context.Canceled) || ownerErr != nil || calls.Load() != 1 {
			t.Fatal("waiter cancellation changed refresh ownership", waiterErr, ownerErr, calls.Load())
		}
	})
}
