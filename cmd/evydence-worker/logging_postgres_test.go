package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/wiring"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type loggingCompletionQueue struct {
	workerQueue
	target string
	cancel context.CancelFunc
}

func (q loggingCompletionQueue) CompleteJob(ctx context.Context, id, lease string) error {
	err := q.workerQueue.CompleteJob(ctx, id, lease)
	if err == nil && id == q.target {
		q.cancel()
	}
	return err
}

func TestHTTPToNativeWorkerLoggingCorrelatesDurableSideEffect(t *testing.T) {
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
	defer admin.Close(context.WithoutCancel(ctx))
	schema := fmt.Sprintf("evydence_logging_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
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
	conn, err := pgx.Connect(ctx, scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, `INSERT INTO ledger_state(id,state)VALUES('default','"logging-aggregate-forbidden"')`); err != nil {
		t.Fatal(err)
	}
	objects, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const pepper = "logging-fixture-pepper-not-a-production-secret"
	bootstrap, err := wiring.BuildTenantBootstrapCommands(store, pepper, false)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := bootstrap.BootstrapFirstTenant(ctx, identityapp.BootstrapTenantInput{TenantName: "CANARY_CUSTOMER", APIKeyName: "fixture", Scopes: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &wiring.Runtime{Process: wiring.API, Profile: wiring.PostgreSQL, Postgres: store, Objects: objects, WorkerOwnedParsers: true}
	options, err := wiring.BuildAPIReadServices(runtime, pepper, []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(checkCtx context.Context) error { return store.CheckMigrationState(checkCtx, "../../migrations") }}})
	if err != nil {
		t.Fatal(err)
	}
	options.PaginationSecret = []byte(pepper)
	var apiLogs, workerLogs bytes.Buffer
	options.Logger, err = logging.New(&apiLogs, "api", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpapi.NewNativeServerWithOptionsContext(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "CANARY_HTTP_CORRELATION"
	post := func(path, key string, body any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+identity.Secret)
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("X-Request-ID", requestID)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("%s status=%d", path, response.Code)
		}
		var data struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data.Data
	}
	product := post("/v1/products", "logging-product", map[string]any{"name": "Product", "slug": "logging"})
	release := post("/v1/releases", "logging-release", map[string]any{"product_id": product["id"], "version": "1"})
	requestID = "CANARY_SBOM_REQUEST"
	sbom := post("/v1/sboms", "CANARY_IDEMPOTENCY_KEY", map[string]any{"release_id": release["id"], "payload": map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []map[string]any{{"type": "library", "name": "CANARY_RAW_EVIDENCE"}}}})
	var parserJob string
	if err := conn.QueryRow(ctx, `SELECT id FROM outbox_jobs WHERE kind='parse_sbom' AND subject_id=$1`, sbom["id"]).Scan(&parserJob); err != nil {
		t.Fatal(err)
	}
	workerLogger, err := logging.New(&workerLogs, "worker", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, stop := context.WithCancel(logging.WithLogger(ctx, workerLogger))
	defer stop()
	processor, err := newNativeJobProcessor(store, objects, defaultMaxWorkerPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := runWorkerLoop(workerCtx, loggingCompletionQueue{store, parserJob, stop}, processor, workerLoopConfig{PollInterval: time.Millisecond, BatchSize: 1, ShutdownTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	var components int
	var state string
	if err := conn.QueryRow(ctx, `SELECT s.component_count,j.status FROM sboms s JOIN outbox_jobs j ON j.subject_id=s.id WHERE j.id=$1`, parserJob).Scan(&components, &state); err != nil || components != 1 || state != "succeeded" {
		t.Fatal("native worker effect missing", components, state, err)
	}
	want := logging.Reference("request", requestID)
	for service, raw := range map[string]string{"api": apiLogs.String(), "worker": workerLogs.String()} {
		if strings.Contains(raw, "CANARY") || strings.Contains(raw, identity.Secret) || strings.Contains(raw, pepper) {
			t.Fatal("private input leaked in " + service)
		}
		found := false
		auditFound := false
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			if event["request_id"] == want {
				if service == "api" && event["msg"] == "http_request" || service == "worker" && event["msg"] == "outbox" && event["result_code"] == "succeeded" {
					found = true
				}
				if event["msg"] == "audit" && event["receipt_id"] != "" {
					auditFound = true
				}
			}
		}
		if !found || service == "api" && !auditFound {
			t.Fatal("request, committed audit or native worker correlation missing for " + service)
		}
	}
}
