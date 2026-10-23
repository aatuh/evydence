package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func workerMetricsRequest(t *testing.T, client *http.Client, address string) (string, error) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), "GET", "http://"+address+"/metrics", nil)
	if err != nil {
		return "", err
	}
	r.Header.Set("Authorization", "Bearer evymetrics_"+strings.Repeat("a", 64))
	response, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err == nil && response.StatusCode != 200 {
		return "", errors.New("worker scrape failed")
	}
	return string(body), err
}

func TestWorkerMetricsLifecycleOwnsBothListenersAndWork(t *testing.T) {
	probes, monitor := workerProbeLifecycleFixture(t)
	metrics, _ := workerProbeLifecycleFixture(t)
	handler := protectedWorkerMetricsHandler(t, &workerMetricsFixture{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, stopped := make(chan struct{}), make(chan bool, 1)
	done := make(chan error, 1)
	go func() {
		done <- runWorkerWithHealth(ctx, probes, monitor, time.Second, func(workCtx context.Context) error {
			close(entered)
			<-workCtx.Done()
			snapshot, err := monitor.Snapshot(context.WithoutCancel(workCtx))
			stopped <- err == nil && snapshot.Draining
			return nil
		}, workerMetricsEndpoint{listener: metrics, handler: handler})
	}()
	workerProbeAwait(t, entered)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	body, err := workerMetricsRequest(t, client, metrics.Addr().String())
	if err != nil || !strings.Contains(body, `service="worker"`) {
		t.Fatal("owned worker metrics endpoint is unavailable", err)
	}
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", probes.Addr().String())
	if err := runWorkerHealthcheck(t.Context(), nil); err != nil {
		t.Fatal("metrics listener replaced worker lifecycle probes", err)
	}
	cancel()
	if !workerProbeAwait(t, stopped) {
		t.Fatal("worker stopped before publishing draining")
	}
	workerProbeAwait(t, probes.closed)
	workerProbeAwait(t, metrics.closed)
	if err := workerProbeAwait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerMetricsServingFailureStopsBothListenersAndWork(t *testing.T) {
	probes, monitor := workerProbeLifecycleFixture(t)
	metrics, _ := workerProbeLifecycleFixture(t)
	metrics.fail = make(chan struct{})
	entered := make(chan struct{})
	done := make(chan error, 1)
	handler := protectedWorkerMetricsHandler(t, &workerMetricsFixture{})
	go func() {
		done <- runWorkerWithHealth(t.Context(), probes, monitor, time.Second, func(ctx context.Context) error { close(entered); <-ctx.Done(); return nil }, workerMetricsEndpoint{listener: metrics, handler: handler})
	}()
	workerProbeAwait(t, entered)
	close(metrics.fail)
	if err := workerProbeAwait(t, done); !errors.Is(err, errProbeAccept) {
		t.Fatal("metrics serving failure was hidden", err)
	}
	workerProbeAwait(t, probes.closed)
	workerProbeAwait(t, metrics.closed)
}

func TestWorkerMetricsForcedDrainPreservesRuntimeExitBoundary(t *testing.T) {
	probes, monitor := workerProbeLifecycleFixture(t)
	metrics, _ := workerProbeLifecycleFixture(t)
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	source := &workerMetricsFixture{read: func(context.Context) (string, error) {
		close(entered)
		defer close(exited)
		<-release
		return "safe_metric 1\n", nil
	}}
	handler := protectedWorkerMetricsHandler(t, source)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runWorkerWithHealth(ctx, probes, monitor, 20*time.Millisecond, func(workCtx context.Context) error { <-workCtx.Done(); return nil }, workerMetricsEndpoint{listener: metrics, handler: handler})
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	responseDone := make(chan struct{})
	go func() { _, _ = workerMetricsRequest(t, client, metrics.Addr().String()); close(responseDone) }()
	workerProbeAwait(t, entered)
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", probes.Addr().String())
	if err := runWorkerHealthcheck(t.Context(), []string{"--liveness"}); err != nil {
		t.Fatal("blocked metrics scrape blocked liveness", err)
	}
	cancel()
	err := workerProbeAwait(t, done)
	if !errors.Is(err, errWorkerProbeDrainTimeout) {
		t.Fatal("noncooperative metrics handler did not force process exit", err)
	}
	closed := false
	closeWorkerAfterStop(err, func() { closed = true })
	if closed {
		t.Fatal("runtime cleanup ran behind a still-owned metrics handler")
	}
	finish()
	workerProbeAwait(t, exited)
	workerProbeAwait(t, responseDone)
	workerProbeAwait(t, probes.closed)
	workerProbeAwait(t, metrics.closed)
}

func TestWorkerMetricsLifecycleClosesListenersOnInvalidOrCanceledStartup(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		probes, monitor := workerProbeLifecycleFixture(t)
		metrics, _ := workerProbeLifecycleFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		var handler http.Handler
		if cancelled {
			cancel()
			handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}
		calls := 0
		err := runWorkerWithHealth(ctx, probes, monitor, time.Second, func(context.Context) error { calls++; return nil }, workerMetricsEndpoint{listener: metrics, handler: handler})
		cancel()
		if calls != 0 || (!cancelled && err == nil) || (cancelled && err != nil) {
			t.Fatal("invalid/canceled startup admitted work or lost cleanup", err, calls)
		}
		workerProbeAwait(t, probes.closed)
		workerProbeAwait(t, metrics.closed)
	}
}
