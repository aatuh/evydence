package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aatuh/evydence/internal/platform/health"
)

func TestWorkerProbeSeparatesLifecycleAndRecoversWithoutDisclosure(t *testing.T) {
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	var schemaDown, objectDown atomic.Bool
	var calls atomic.Int64
	monitor, err := health.New([]health.Check{
		{Name: "migrations", Startup: true, Check: func(context.Context) error {
			calls.Add(1)
			if schemaDown.Load() {
				return errors.New("private-postgres-address-and-password")
			}
			return nil
		}},
		{Name: "object_store", Check: func(context.Context) error {
			calls.Add(1)
			if objectDown.Load() {
				return errors.New("private-object-address-and-token")
			}
			return nil
		}},
	}, health.Config{Now: func() time.Time { return time.Unix(0, clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	handler := newWorkerHealthHandler(monitor)
	check := func(path string, code int) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != code || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "private-") {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body)
		}
	}
	check("/v1/health", 200)
	check("/v1/startup", 503)
	check("/v1/ready", 503)
	if calls.Load() != 0 {
		t.Fatal("uninitialized/liveness probes touched dependencies")
	}
	monitor.MarkInitialized()
	check("/v1/startup", 200)
	check("/v1/ready", 200)
	if calls.Load() != 2 {
		t.Fatal("startup/readiness did not share one dependency sample")
	}
	objectDown.Store(true)
	clock.Add(int64(3 * time.Second))
	check("/v1/ready", 503)
	check("/v1/startup", 200)
	check("/v1/health", 200)
	schemaDown.Store(true)
	clock.Add(int64(3 * time.Second))
	check("/v1/startup", 503)
	check("/v1/ready", 503)
	check("/v1/health", 200)
	schemaDown.Store(false)
	objectDown.Store(false)
	clock.Add(int64(3 * time.Second))
	check("/v1/ready", 200)
	check("/v1/startup", 200)
	before := calls.Load()
	monitor.MarkDraining()
	check("/v1/startup", 503)
	check("/v1/ready", 503)
	check("/v1/health", 200)
	if calls.Load() != before {
		t.Fatal("draining probes did dependency work")
	}
}

func TestWorkerProbeBoundsAdmissionWithoutStarvingLiveness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int64
		monitor, err := health.New([]health.Check{{Name: "postgres", Check: func(ctx context.Context) error {
			calls.Add(1)
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}}, health.Config{})
		if err != nil {
			t.Fatal(err)
		}
		monitor.MarkInitialized()
		handler := newWorkerHealthHandler(monitor)
		done := make(chan int, 8)
		for range 8 {
			go func() {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
				done <- response.Code
			}()
		}
		<-entered
		synctest.Wait()
		for path, code := range map[string]int{"/v1/ready": 503, "/v1/startup": 503, "/v1/health": 200} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != code {
				t.Fatalf("saturated %s status=%d", path, response.Code)
			}
		}
		close(release)
		for range 8 {
			if code := <-done; code != 200 {
				t.Fatalf("admitted probe failed: %d", code)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("probe storm caused %d dependency checks", calls.Load())
		}
	})
}

func TestWorkerProbeRejectsUnexpectedRequestsBeforeDependencyWork(t *testing.T) {
	calls := 0
	monitor, err := health.New([]health.Check{{Name: "postgres", Check: func(context.Context) error { calls++; return nil }}}, health.Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	handler := newWorkerHealthHandler(monitor)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/ready", ""}, {http.MethodGet, "/v1/admin/readiness", ""},
		{http.MethodGet, "/v1/%72eady", ""}, {http.MethodGet, "/v1/ready?private-token=secret", ""},
		{http.MethodGet, "/v1/ready", "private-payload"}, {http.MethodGet, "/" + strings.Repeat("x", 2048), ""},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if response.Code < 400 || strings.Contains(response.Body.String(), "private-") {
			t.Fatal("unexpected request accepted or disclosed", response.Code, response.Body)
		}
	}
	if calls != 0 {
		t.Fatal("rejected requests touched dependencies")
	}
}

func TestWorkerProbeCommandQueriesRunningWorkerAndRejectsOtherProcesses(t *testing.T) {
	monitor, err := health.New(nil, health.Config{})
	if err != nil {
		t.Fatal(err)
	}
	monitor.MarkInitialized()
	server := httptest.NewServer(newWorkerHealthHandler(monitor))
	defer server.Close()
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", server.Listener.Addr().String())
	for _, args := range [][]string{nil, {"--startup"}, {"--liveness"}} {
		if err := runWorkerHealthcheck(t.Context(), args); err != nil {
			t.Fatal("running worker probe failed", err)
		}
	}
	monitor.MarkDraining()
	if err := runWorkerHealthcheck(t.Context(), nil); err == nil {
		t.Fatal("draining worker reported ready")
	}
	if err := runWorkerHealthcheck(t.Context(), []string{"--liveness"}); err != nil {
		t.Fatal("drain incorrectly disabled liveness", err)
	}
	server.Close()
	if err := runWorkerHealthcheck(t.Context(), nil); err == nil {
		t.Fatal("absent worker reported healthy")
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"status":"ok"},"meta":{"process":"api"}}`))
	}))
	defer other.Close()
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", other.Listener.Addr().String())
	if err := runWorkerHealthcheck(t.Context(), nil); err == nil {
		t.Fatal("API process was mistaken for a worker")
	}
}

func TestWorkerProbeCommandValidatesLocalAddressFlagsAndCancellation(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8081", "192.0.2.1:8081", "localhost:8081", "127.0.0.1:0", "http://127.0.0.1:8081", "127.0.0.1:8081/private"} {
		t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", address)
		if err := runWorkerHealthcheck(t.Context(), nil); err == nil {
			t.Fatal("invalid local probe address accepted")
		}
	}
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", "127.0.0.1:8081")
	for _, args := range [][]string{{"--liveness", "--startup"}, {"unexpected"}, {"--private-token=secret"}} {
		if err := runWorkerHealthcheck(t.Context(), args); err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatal("invalid flags accepted/disclosed", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runWorkerHealthcheck(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestWorkerProbeMainRejectsBadHealthConfigurationBeforeStorage(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", "0.0.0.0:8081")
	if err := runWorkerWithContext(t.Context(), nil); err == nil || !strings.Contains(err.Error(), "EVYDENCE_WORKER_HEALTH_ADDR") {
		t.Fatal("invalid listener configuration reached storage validation", err)
	}
}

func TestWorkerProbeMainCommandRequiresRunningWorker(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.Listener.Addr().String()
	server.Close()
	t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", address)
	for _, command := range []string{"healthcheck", "--healthcheck"} {
		if err := runWorkerWithContext(t.Context(), []string{command}); err == nil {
			t.Fatal("command reported success without a running worker")
		}
	}
}

func TestWorkerProbeCommandRejectsRedirectsMalformedAndOversizedReplies(t *testing.T) {
	var sinkCalls atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sinkCalls.Add(1) }))
	defer sink.Close()
	for _, body := range []string{"redirect", "private-invalid-response", `{"data":{"status":"ok"},"meta":{"process":"worker"}}` + strings.Repeat(" ", 4096)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if body == "redirect" {
				http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		t.Setenv("EVYDENCE_WORKER_HEALTH_ADDR", server.Listener.Addr().String())
		err := runWorkerHealthcheck(t.Context(), nil)
		server.Close()
		if err == nil || strings.Contains(err.Error(), "private-") || sinkCalls.Load() != 0 {
			t.Fatal("invalid/redirected health response accepted or disclosed", err)
		}
	}
}
