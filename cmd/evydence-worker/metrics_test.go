package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type workerMetricsFixture struct {
	reads atomic.Int64
	read  func(context.Context) (string, error)
}

func (f *workerMetricsFixture) Snapshot(ctx context.Context) (string, error) {
	f.reads.Add(1)
	if f.read != nil {
		return f.read(ctx)
	}
	return "evydence_operations_total{service=\"worker\",operation=\"worker_process\",outcome=\"succeeded\"} 2\n", nil
}

func protectedWorkerMetricsHandler(t *testing.T, source *workerMetricsFixture) http.Handler {
	t.Helper()
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", workerMetricsTokenFixture(t))
	cfg, err := workerMetricsConfigFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newWorkerMetricsHandler(cfg, source)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWorkerMetricsRequiresDistinctOperatorBearerBeforeSnapshot(t *testing.T) {
	source := &workerMetricsFixture{}
	h := protectedWorkerMetricsHandler(t, source)
	for _, headers := range [][]string{nil, {"Basic PRIVATE_TOKEN"}, {"Bearer evysso_PRIVATE_TENANT_SESSION"}, {"Bearer evy_PRIVATE_TENANT_KEY"}, {"Bearer evymetrics_" + strings.Repeat("b", 64)}, {"Bearer evymetrics_" + strings.Repeat("a", 64), "Bearer duplicate"}, {strings.Repeat("PRIVATE", 1000)}} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		for _, header := range headers {
			r.Header.Add("Authorization", header)
		}
		r.Header.Set("Cookie", "session=PRIVATE_COOKIE")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || source.reads.Load() != 0 || strings.Contains(w.Body.String(), "PRIVATE") || strings.Contains(w.Body.String(), "operations_total") {
			t.Fatal("unverified worker credential read or exposed process data", w.Code)
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "/metrics", nil)
		r.Header.Set("Authorization", "Bearer evymetrics_"+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
			t.Fatal("authorized worker scrape failed", w.Code)
		}
		if method == "GET" && !strings.Contains(w.Body.String(), `service="worker"`) {
			t.Fatal("worker scrape lost real measurements")
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD scrape emitted a body")
		}
	}
	if source.reads.Load() != 2 {
		t.Fatal("authorized scrape did not read exactly once per request")
	}
}

func TestWorkerMetricsRejectsMalformedRequestsBeforeResourceRead(t *testing.T) {
	source := &workerMetricsFixture{}
	h := protectedWorkerMetricsHandler(t, source)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/metrics", "", 405}, {"GET", "/metrics?token=PRIVATE", "", 400}, {"GET", "/metrics?", "", 400}, {"GET", "/metrics", "PRIVATE", 400}, {"GET", "/metrics/", "", 404}, {"GET", "/%6detrics", "", 404}, {"GET", "/v1/ready", "", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer evymetrics_"+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || source.reads.Load() != 0 || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("malformed scrape reached resource reader", tc.path, w.Code)
		}
	}
}

func TestWorkerMetricsAdmissionAndCancellationProtectResourceReader(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	source := &workerMetricsFixture{read: func(ctx context.Context) (string, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return "evydence_queue_jobs 0\n", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}}
	h := protectedWorkerMetricsHandler(t, source)
	request := func(ctx context.Context) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/metrics", nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer evymetrics_"+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var joined sync.WaitGroup
	for range 4 {
		joined.Go(func() {
			if w := request(t.Context()); w.Code != 200 {
				t.Error("admitted scrape failed", w.Code)
			}
		})
	}
	for range 4 {
		workerProbeAwait(t, entered)
	}
	if w := request(t.Context()); w.Code != 503 || source.reads.Load() != 4 {
		t.Fatal("saturated scrape performed extra resource work", w.Code)
	}
	finish()
	joined.Wait()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if w := request(canceled); w.Code != 503 || source.reads.Load() != 4 {
		t.Fatal("canceled scrape accessed resources", w.Code)
	}
	if w := request(t.Context()); w.Code != 200 || source.reads.Load() != 5 {
		t.Fatal("scrape admission did not recover", w.Code)
	}
}

func TestWorkerMetricsUnavailableOrPanickingSnapshotExposesNoPartialData(t *testing.T) {
	for _, mode := range []string{"error", "panic", "oversized"} {
		source := &workerMetricsFixture{read: func(context.Context) (string, error) {
			if mode == "panic" {
				panic("PRIVATE_DATABASE_URI")
			}
			if mode == "oversized" {
				return strings.Repeat("x", (8<<20)+1), nil
			}
			return "PRIVATE_PARTIAL_METRICS", errors.New("PRIVATE_CREDENTIAL")
		}}
		h := protectedWorkerMetricsHandler(t, source)
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "Bearer evymetrics_"+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE") || w.Body.Len() > 1024 || w.Header().Get("Retry-After") == "" {
			t.Fatal("failed scrape exposed raw/partial data", mode, w.Code)
		}
	}
}

func TestWorkerMetricsCredentialRotationRevokesOldValueAfterRestart(t *testing.T) {
	file := workerMetricsTokenFixture(t)
	t.Setenv("EVYDENCE_WORKER_METRICS_ADDR", "")
	t.Setenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE", file)
	source := &workerMetricsFixture{}
	config, err := workerMetricsConfigFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	before, err := newWorkerMetricsHandler(config, source)
	if err != nil {
		t.Fatal(err)
	}
	rotated := "evymetrics_" + strings.Repeat("b", 64)
	if err := os.WriteFile(file, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	config, err = workerMetricsConfigFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	after, err := newWorkerMetricsHandler(config, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		handler http.Handler
		token   string
		status  int
	}{
		{before, "evymetrics_" + strings.Repeat("a", 64), 200}, {before, rotated, 401},
		{after, "evymetrics_" + strings.Repeat("a", 64), 401}, {after, rotated, 200},
	} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		tc.handler.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "evymetrics_") {
			t.Fatal("loaded/restarted credential lifecycle changed or disclosed a secret", w.Code)
		}
	}
	if source.reads.Load() != 2 {
		t.Fatal("rejected credential rotation values accessed resources", source.reads.Load())
	}
}
