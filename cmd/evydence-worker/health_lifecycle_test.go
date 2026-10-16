package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/health"
)

type workerProbeListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
	fail   chan struct{}
}

var errProbeAccept = errors.New("injected worker probe accept failure")

func (l *workerProbeListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func (l *workerProbeListener) Accept() (net.Conn, error) {
	if l.fail != nil {
		select {
		case <-l.fail:
			return nil, errProbeAccept
		case <-l.closed:
			return nil, net.ErrClosed
		}
	}
	return l.Listener.Accept()
}

func workerProbeLifecycleFixture(t *testing.T) (*workerProbeListener, *health.Monitor) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	monitor, err := health.New(nil, health.Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	return &workerProbeListener{Listener: listener, closed: make(chan struct{})}, monitor
}

func workerProbeAwait[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case result := <-events:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("worker probe lifecycle event timed out")
		var zero T
		return zero
	}
}

func TestWorkerProbeLifecycleMarksDrainingBeforeStoppingAndJoinsWork(t *testing.T) {
	listener, monitor := workerProbeLifecycleFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, stopped, release := make(chan struct{}), make(chan bool, 1), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	done := make(chan error, 1)
	go func() {
		done <- runWorkerWithHealth(ctx, listener, monitor, time.Second, func(workCtx context.Context) error {
			close(entered)
			<-workCtx.Done()
			status, err := monitor.Snapshot(context.WithoutCancel(workCtx))
			stopped <- err == nil && status.Draining && !status.Ready
			<-release // Admitted work retains its own native drain lifetime.
			return nil
		})
	}()
	workerProbeAwait(t, entered)
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", listener.Addr().String())
	if err := runWorkerHealthcheck(t.Context(), nil); err != nil {
		t.Fatal("running worker was not ready", err)
	}
	cancel()
	if !workerProbeAwait(t, stopped) {
		t.Fatal("work cancellation preceded draining publication")
	}
	workerProbeAwait(t, listener.closed)
	select {
	case err := <-done:
		t.Fatal("owner returned before work drain completed", err)
	default:
	}
	finish()
	if err := workerProbeAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if err := runWorkerHealthcheck(t.Context(), []string{"--liveness"}); err == nil {
		t.Fatal("stopped worker remained live")
	}
}

func TestWorkerProbeLifecycleServingFailureStopsAndJoinsWork(t *testing.T) {
	listener, monitor := workerProbeLifecycleFixture(t)
	listener.fail = make(chan struct{})
	entered, canceled := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runWorkerWithHealth(t.Context(), listener, monitor, time.Second, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return nil
		})
	}()
	workerProbeAwait(t, entered)
	close(listener.fail)
	if err := workerProbeAwait(t, done); !errors.Is(err, errProbeAccept) {
		t.Fatal("serving failure was hidden", err)
	}
	workerProbeAwait(t, canceled)
	workerProbeAwait(t, listener.closed)
	status, err := monitor.Snapshot(t.Context())
	if err != nil || !status.Draining {
		t.Fatal("failed probe server still reported ready", err)
	}
}

func TestWorkerProbeLifecyclePropagatesWorkFailureAndForcedDrain(t *testing.T) {
	for _, workErr := range []error{errors.New("work failed"), errWorkerDrainTimeout} {
		listener, monitor := workerProbeLifecycleFixture(t)
		if err := runWorkerWithHealth(t.Context(), listener, monitor, time.Second, func(context.Context) error { return workErr }); !errors.Is(err, workErr) {
			t.Fatal("worker failure was lost", err)
		}
		workerProbeAwait(t, listener.closed)
	}
}

func TestWorkerProbeLifecycleRejectsCancelledStartupAndPreservesRootDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		listener, monitor := workerProbeLifecycleFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if expired {
			ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
		}
		var calls atomic.Int64
		err := runWorkerWithHealth(ctx, listener, monitor, time.Second, func(context.Context) error { calls.Add(1); return nil })
		if calls.Load() != 0 || (expired && !errors.Is(err, context.DeadlineExceeded)) || (!expired && err != nil) {
			t.Fatal("invalid startup claimed work or lost deadline", err)
		}
		workerProbeAwait(t, listener.closed)
	}
}

func TestWorkerProbeLifecycleForcedHTTPDrainPreservesExitBoundary(t *testing.T) {
	listener, _ := workerProbeLifecycleFixture(t)
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	monitor, err := health.New([]health.Check{{Name: "postgres", Check: func(context.Context) error {
		close(entered)
		defer close(exited)
		<-release // Model a noncooperative adapter until forced process exit.
		return nil
	}}}, health.Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runWorkerWithHealth(ctx, listener, monitor, 20*time.Millisecond, func(workCtx context.Context) error { <-workCtx.Done(); return nil })
	}()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String()+"/v1/ready", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	responseDone := make(chan struct{})
	go func() {
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
		close(responseDone)
	}()
	workerProbeAwait(t, entered)
	cancel()
	err = workerProbeAwait(t, done)
	if !errors.Is(err, errWorkerProbeDrainTimeout) {
		t.Fatal("noncooperative probe did not force process exit", err)
	}
	closed := false
	closeWorkerAfterStop(err, func() { closed = true })
	if closed {
		t.Fatal("runtime cleanup waited behind a still-owned probe")
	}
	finish()
	workerProbeAwait(t, exited)
	workerProbeAwait(t, responseDone)
}
