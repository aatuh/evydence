package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/telemetry/oteltrace"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type workerTraceProcessResult struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
}

// The parent invokes this exact test in a fresh process, with an isolated real
// database schema and the public certificate of its local collector fixture.
func TestWorkerTraceProcessHelper(t *testing.T) {
	if os.Getenv("EVYDENCE_WORKER_TRACE_HELPER") != "1" {
		return
	}
	ctx := t.Context()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(os.Getenv("EVYDENCE_WORKER_TRACE_HELPER_CA"))) {
		t.Fatal("missing owned collector trust")
	}
	adapter, err := oteltrace.New(ctx, oteltrace.Config{
		Enabled: true, Service: "worker", Endpoint: os.Getenv("EVYDENCE_WORKER_TRACE_HELPER_ENDPOINT"),
		SamplePerMillion: 1000000, QueueSize: 16, ExportTimeout: time.Second, ShutdownTimeout: 2 * time.Second,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adapter.Shutdown(context.WithoutCancel(ctx)) }()
	store, err := postgres.OpenWithOptions(ctx, os.Getenv("EVYDENCE_WORKER_TRACE_HELPER_DATABASE_URL"), postgres.StoreOptions{LoadMode: postgres.LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	jobs, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(jobs) != 1 || !jobs[0].TraceContext.Valid() {
		t.Fatal("fresh worker process did not restore durable trace context", err)
	}
	var result workerTraceProcessResult
	processor := lifecycleProcessor(func(callCtx context.Context, _ postgres.ClaimedJob) error {
		carrier := telemetry.TraceContextFromContext(callCtx)
		if !carrier.Valid() || carrier.TraceID() != jobs[0].TraceContext.TraceID() || carrier.SpanID() == jobs[0].TraceContext.SpanID() {
			return errors.New("worker trace lost durable parentage")
		}
		result = workerTraceProcessResult{TraceID: carrier.TraceID(), SpanID: carrier.SpanID()}
		return telemetry.MeasureError(callCtx, telemetry.OperationProviderSign, func(providerCtx context.Context) error {
			if providerCtx != callCtx {
				return errors.New("provider measurement changed caller context")
			}
			return nil
		})
	})
	if err := drainableWorkerJob(telemetry.WithObserver(ctx, adapter), store, processor, jobs[0], time.Second); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	output := os.NewFile(3, "worker-trace-result")
	if output == nil {
		t.Fatal("missing inherited result pipe")
	}
	defer func() { _ = output.Close() }()
	if _, err := output.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerTraceSurvivesPostgresAndFreshProcessWithoutPayloadExposure(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.WithoutCancel(ctx)) }()
	schema := "evydence_worker_trace_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	scopedURL := postgresURLWithSearchPath(t, databaseURL, schema)
	store, err := postgres.OpenWithOptions(ctx, scopedURL, postgres.StoreOptions{LoadMode: postgres.LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO "+quoted+`.tenants(id,name)VALUES('trace_tenant','PRIVATE_TENANT')`); err != nil {
		t.Fatal(err)
	}
	requests := make(chan []byte, 16)
	collector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			t.Error(err)
			return
		}
		requests <- body
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()
	api, err := oteltrace.New(ctx, oteltrace.Config{Enabled: true, Service: "api", Endpoint: collector.URL + "/v1/traces", SamplePerMillion: 1000000, QueueSize: 16, ExportTimeout: time.Second, ShutdownTimeout: 2 * time.Second, HTTPClient: collector.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = api.Shutdown(context.WithoutCancel(ctx)) }()
	origin, finish := telemetry.BeginTrace(telemetry.WithObserver(ctx, api), telemetry.TraceHTTP)
	parent := telemetry.TraceContextFromContext(origin)
	if !parent.Valid() {
		t.Fatal("API did not create an internal trace context")
	}
	if err := store.Enqueue(origin, app.OutboxJob{ID: "trace_job", TenantID: "trace_tenant", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "PRIVATE_SUBJECT", Payload: map[string]any{"source": "PRIVATE_EVIDENCE"}, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	finish(telemetry.OutcomeSucceeded)
	if err := api.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	store.Close()
	resultReader, resultWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultReader.Close() }()
	defer func() { _ = resultWriter.Close() }()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestWorkerTraceProcessHelper$", "-test.timeout=15s")
	command.ExtraFiles = []*os.File{resultWriter}
	command.Env = append(os.Environ(),
		"EVYDENCE_WORKER_TRACE_HELPER=1", "EVYDENCE_WORKER_TRACE_HELPER_DATABASE_URL="+scopedURL,
		"EVYDENCE_WORKER_TRACE_HELPER_ENDPOINT="+collector.URL+"/v1/traces",
		"EVYDENCE_WORKER_TRACE_HELPER_CA="+string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: collector.Certificate().Raw})),
	)
	var diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &diagnostics, &diagnostics
	if err := command.Run(); err != nil {
		t.Fatal("fresh worker process failed", err, diagnostics.String())
	}
	if err := resultWriter.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(resultReader, 1024))
	if err != nil {
		t.Fatal(err)
	}
	var worker workerTraceProcessResult
	if err := json.Unmarshal(data, &worker); err != nil || worker.TraceID != parent.TraceID() || worker.SpanID == parent.SpanID() {
		t.Fatal("fresh process lost source trace continuity", err)
	}
	var state, payload string
	if err := admin.QueryRow(ctx, "SELECT status,payload->>'source' FROM "+quoted+`.outbox_jobs WHERE id='trace_job'`).Scan(&state, &payload); err != nil || state != "succeeded" || payload != "PRIVATE_EVIDENCE" {
		t.Fatal("trace propagation changed the durable job outcome or payload", err)
	}
	traceID, err := hex.DecodeString(parent.TraceID())
	if err != nil {
		t.Fatal(err)
	}
	apiParent, err := hex.DecodeString(parent.SpanID())
	if err != nil {
		t.Fatal(err)
	}
	workerParent, err := hex.DecodeString(worker.SpanID)
	if err != nil {
		t.Fatal(err)
	}
	foundWorker, foundProvider := false, false
	for len(requests) > 0 {
		body := <-requests
		if bytes.Contains(body, []byte("PRIVATE")) {
			t.Fatal("durable trace exported tenant, subject or evidence data")
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					if !bytes.Equal(span.TraceId, traceID) {
						t.Fatal("worker/provider span escaped the originating trace")
					}
					if span.Name == string(telemetry.TraceWorker) {
						foundWorker = bytes.Equal(span.ParentSpanId, apiParent)
					}
					if span.Name == string(telemetry.OperationProviderSign) {
						foundProvider = bytes.Equal(span.ParentSpanId, workerParent)
					}
				}
			}
		}
	}
	if !foundWorker || !foundProvider {
		t.Fatal("collector did not receive the durable worker/provider parent chain")
	}
}
