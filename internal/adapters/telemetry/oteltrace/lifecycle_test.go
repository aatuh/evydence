package oteltrace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestTraceConfigurationDiagnosticsAreRedacted(t *testing.T) {
	config := Config{Endpoint: "https://PRIVATE_COLLECTOR.invalid/v1/traces"}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data)+fmt.Sprintf("%v %#v", config, config), "PRIVATE") {
		t.Fatal("trace configuration diagnostics disclosed a collector URL")
	}
}

func TestUnavailableCollectorCannotChangeApplicationOutcomeOrRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "PRIVATE_COLLECTOR_FAILURE", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	adapter, err := New(t.Context(), traceTestConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithObserver(t.Context(), adapter)
	ctx, finish := telemetry.BeginTrace(ctx, telemetry.TraceHTTP)
	appError := errors.New("PRIVATE_APPLICATION_ERROR")
	if err := telemetry.MeasureError(ctx, telemetry.OperationProviderIdentity, func(context.Context) error { return appError }); err != appError {
		t.Fatal("collector failure replaced the application result")
	}
	finish(telemetry.OutcomeFailed)
	if err := adapter.Shutdown(t.Context()); err != nil && strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("export failure exposed collector or application detail")
	}
	if calls.Load() != 1 {
		t.Fatal("unavailable collector triggered retries or was never called", calls.Load())
	}
}

func TestTraceQueueDropsWithoutBlockingAdmittedWork(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enteredOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var exported atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			t.Error(err)
			return
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for range scope.Spans {
					exported.Add(1)
				}
			}
		}
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	config := traceTestConfig(server)
	config.ExportTimeout, config.ShutdownTimeout = 5*time.Second, 5*time.Second
	adapter, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); _ = adapter.Shutdown(context.WithoutCancel(t.Context())) }()
	adapter.Observe(t.Context(), telemetry.Event{Operation: telemetry.OperationWorkerClaim, Outcome: telemetry.OutcomeSucceeded})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("owned batch worker did not reach the collector")
	}
	recorded := make(chan struct{})
	go func() {
		for range 128 {
			adapter.Observe(t.Context(), telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeSucceeded})
		}
		close(recorded)
	}()
	select {
	case <-recorded:
	case <-time.After(time.Second):
		t.Fatal("full trace queue blocked application recording")
	}
	unblock()
	if err := adapter.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count := exported.Load(); count <= 1 || count > 17 {
		t.Fatal("trace queue did not enforce its 16-span bound behind one active export", count)
	}
}

func TestTraceShutdownCancelsOwnedNetworkWorkAndPreservesCallerCancellation(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1024*1024)); err != nil {
			t.Error(err)
			return
		}
		close(entered)
		<-r.Context().Done()
		close(exited)
	}))
	defer server.Close()
	config := traceTestConfig(server)
	config.ExportTimeout, config.ShutdownTimeout = 5*time.Second, time.Second
	adapter, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adapter.Shutdown(context.WithoutCancel(t.Context())) }()
	root, cancel := context.WithCancel(telemetry.WithObserver(t.Context(), adapter))
	child, finish := telemetry.BeginTrace(root, telemetry.TraceHTTP)
	cancel()
	if child.Err() != context.Canceled || child.Done() != root.Done() {
		t.Fatal("trace scope lost caller cancellation")
	}
	finish(telemetry.OutcomeCanceled)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("owned batch worker did not start export")
	}
	shutdown, cancelShutdown := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelShutdown()
	started := time.Now()
	if err := adapter.Shutdown(shutdown); err != nil && err != errExport {
		t.Fatal("shutdown exposed an unclassified provider error")
	}
	if time.Since(started) > time.Second {
		t.Fatal("trace shutdown exceeded its owned bound")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("trace shutdown left a collector request running")
	}
	select {
	case <-adapter.client.done:
	case <-time.After(time.Second):
		t.Fatal("trace shutdown did not release owned active requests")
	}
	if child, finish := adapter.BeginTrace(root, telemetry.TraceHTTP); child != root {
		t.Fatal("stopped trace owner admitted another span")
	} else {
		finish(telemetry.OutcomeSucceeded)
	}
}
