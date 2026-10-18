//go:build releasebinary

// Package lifecyclecheck exercises ordinary release-style process entry points.
// It is mandatory in black-box-release-artifact-check, not a default unit suite.
package lifecyclecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

const fixturePepper = "lifecycle-fixture-pepper-not-for-production"

type child struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
	log     *os.File
}

type fixture struct {
	createdSchema                                             bool
	requests                                                  sync.WaitGroup
	t                                                         *testing.T
	databaseURL, schema, tenant, secret, objects, artifactDir string
	signerURL, signerCAFile                                   string
	admin, conn                                               *pgx.Conn
	store                                                     *postgres.Store
	children                                                  []*child
	locks                                                     []pgx.Tx
}

func must(t *testing.T, err error, stage string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", stage, redaction.Error(err))
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("EVYDENCE_TEST_DATABASE_URL is required")
	}
	artifactRoot := os.Getenv("EVYDENCE_LIFECYCLE_ARTIFACT_DIR")
	if artifactRoot == "" {
		t.Fatal("EVYDENCE_LIFECYCLE_ARTIFACT_DIR is required")
	}
	tmpRoot, err := filepath.Abs("../../../tmp")
	must(t, err, "resolve repository artifact root")
	artifactRoot, err = filepath.Abs(artifactRoot)
	must(t, err, "resolve lifecycle artifact directory")
	relative, err := filepath.Rel(tmpRoot, artifactRoot)
	must(t, err, "validate lifecycle artifact scope")
	if relative == "." || !filepath.IsLocal(relative) {
		t.Fatal("lifecycle artifacts must stay beneath repository tmp")
	}
	for path := artifactRoot; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path) // #nosec G703 -- Inspect, never follow, validated in-scope ancestors to reject symlinks before OpenRoot.
		must(t, err, "validate existing artifact ancestors")
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("lifecycle artifact ancestors must not be symlinks")
		}
		if path == tmpRoot {
			break
		}
	}
	directory := filepath.Join(artifactRoot, t.Name())
	root, err := os.OpenRoot(artifactRoot)
	must(t, err, "open contained artifact root")
	err = root.Mkdir(t.Name(), 0700)
	_ = root.Close()
	must(t, err, "create isolated case artifacts")
	f := &fixture{t: t, schema: fmt.Sprintf("evy_lifecycle_%d", time.Now().UnixNano()), objects: filepath.Join(directory, "objects"), artifactDir: directory}
	f.configureSigner()
	f.admin, err = pgx.Connect(t.Context(), base)
	must(t, err, "connect fixture admin")
	t.Cleanup(f.close)
	_, err = f.admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{f.schema}.Sanitize())
	must(t, err, "create isolated schema")
	f.createdSchema = true
	parsed, err := url.Parse(base)
	must(t, err, "parse fixture database configuration")
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		t.Fatal("fixture requires a PostgreSQL URL")
	}
	query := parsed.Query()
	query.Set("search_path", f.schema)
	parsed.RawQuery = query.Encode()
	f.databaseURL = parsed.String()
	f.conn, err = pgx.Connect(t.Context(), f.databaseURL)
	must(t, err, "connect fixture schema")
	f.store, err = postgres.Open(t.Context(), f.databaseURL)
	must(t, err, "open fixture store")
	_, err = f.store.ApplyMigrations(t.Context(), "../../../migrations")
	must(t, err, "apply fixture migrations")
	bootstrap, err := wiring.BuildTenantBootstrapCommands(f.store, fixturePepper, true)
	must(t, err, "compose native bootstrap")
	result, err := bootstrap.BootstrapFirstTenant(t.Context(), identityapp.BootstrapTenantInput{TenantName: "Lifecycle fixture", APIKeyName: "Lifecycle admin", Scopes: []string{"*"}})
	must(t, err, "bootstrap native tenant")
	if !result.Created || result.Secret == "" {
		t.Fatal("native bootstrap did not create credentials")
	}
	f.tenant, f.secret = result.Tenant.ID, result.Secret
	_, err = f.conn.Exec(t.Context(), `INSERT INTO ledger_state(id,state)VALUES('default','"aggregate-forbidden"')`)
	must(t, err, "seed aggregate canary")
	_, err = f.conn.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug)VALUES('product',$1,'Lifecycle product','lifecycle-product')`, f.tenant)
	must(t, err, "seed native catalog fixture")
	return f
}

func (f *fixture) close() {
	for _, process := range f.children {
		select {
		case <-process.done:
		default:
			_ = process.command.Process.Kill()
			<-process.done
		}
		_ = process.log.Close()
		data, err := os.ReadFile(process.log.Name())
		if err == nil && (bytes.Contains(data, []byte(f.secret)) && f.secret != "" || bytes.Contains(data, []byte(fixturePepper))) {
			if err := os.WriteFile(process.log.Name(), []byte("fixture credentials detected; diagnostic contents removed\n"), 0600); err != nil {
				f.t.Error("could not scrub unsafe fixture diagnostics")
			}
			f.t.Error("process diagnostics leaked fixture credentials")
		}
	}
	f.requests.Wait()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, lock := range f.locks {
		_ = lock.Rollback(cleanup)
	}
	if f.conn != nil {
		_ = f.conn.Close(cleanup)
	}
	if f.store != nil {
		f.store.Close()
	}
	if f.admin != nil {
		if f.createdSchema {
			_, err := f.admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE")
			if err != nil {
				f.t.Error("fixture schema cleanup failed")
			}
		}
		_ = f.admin.Close(cleanup)
	}
}

func (f *fixture) configureSigner() {
	f.t.Helper()
	server := newReadinessTLSKMSFixture(f.t)
	root, err := os.OpenRoot(f.artifactDir)
	must(f.t, err, "open private signer trust directory")
	err = root.WriteFile("signer-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	closeErr := root.Close()
	must(f.t, err, "write fixture signer trust")
	must(f.t, closeErr, "close fixture signer trust directory")
	f.signerURL, f.signerCAFile = server.URL, filepath.Join(f.artifactDir, "signer-ca.pem")
}

func (f *fixture) processEnvironment(kind, label, budget, address string) []string {
	f.t.Helper()
	parsed, err := url.Parse(f.databaseURL)
	must(f.t, err, "prepare process database scope")
	query := parsed.Query()
	query.Set("application_name", f.schema+"_"+label)
	parsed.RawQuery = query.Encode()
	environment := make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if name != "ENV" && name != "SSL_CERT_FILE" && !strings.HasPrefix(name, "EVYDENCE_") && !strings.HasPrefix(name, "AWS_") {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "ENV=production", "EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL="+parsed.String(), "EVYDENCE_POSTGRES_LOAD_MODE=relational_only", "EVYDENCE_SKIP_MIGRATIONS=true", "EVYDENCE_BOOTSTRAP_DISABLED=true", "EVYDENCE_PRINT_BOOTSTRAP_SECRET=false", "EVYDENCE_API_KEY_PEPPER="+fixturePepper, "EVYDENCE_OBJECT_STORE=filesystem", "EVYDENCE_OBJECT_DIR="+f.objects,
		"EVYDENCE_SIGNING_KEY_MODE=aws-kms", "EVYDENCE_AWS_REGION=eu-north-1", "EVYDENCE_AWS_KMS_KEY_ID=alias/lifecycle-fixture", "EVYDENCE_AWS_KMS_ENDPOINT="+f.signerURL,
		"AWS_ACCESS_KEY_ID=fixture-access", "AWS_SECRET_ACCESS_KEY=fixture-secret", "AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE="+os.DevNull, "AWS_SHARED_CREDENTIALS_FILE="+os.DevNull,
		"SSL_CERT_FILE="+f.signerCAFile,
		"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=2", "EVYDENCE_WORKER_POLL_INTERVAL=10ms", "EVYDENCE_WORKER_BATCH_SIZE=1", "EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS="+budget, "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS="+budget)
	migrations, err := filepath.Abs("../../../migrations")
	must(f.t, err, "resolve migration directory")
	environment = append(environment, "EVYDENCE_MIGRATIONS_DIR="+migrations)
	switch kind {
	case "api":
		environment = append(environment, "EVYDENCE_ADDR="+address)
	case "worker":
		environment = append(environment, "EVYDENCE_WORKER_HEALTH_ADDR="+address)
	}
	return environment
}

func (f *fixture) start(kind, label, budget, address string) *child {
	f.t.Helper()
	variable := "EVYDENCE_LIFECYCLE_" + strings.ToUpper(kind) + "_BIN"
	binary, err := filepath.Abs(os.Getenv(variable))
	must(f.t, err, "resolve release binary")
	info, err := os.Stat(binary) // #nosec G703 -- Trusted operator selects a release executable; this is not an API/upload path.
	must(f.t, err, "read release binary")
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		f.t.Fatal("release binary must be an executable file")
	}
	if kind == "worker" && address == "" {
		reserved, err := net.Listen("tcp", "127.0.0.1:0")
		must(f.t, err, "reserve worker probe address")
		address = reserved.Addr().String()
		must(f.t, reserved.Close(), "release worker probe address")
	}
	environment := f.processEnvironment(kind, label, budget, address)
	log, err := os.OpenFile(filepath.Join(f.artifactDir, strings.ReplaceAll(label, ":", "_")+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(f.t, err, "open private process log")
	command := exec.CommandContext(f.t.Context(), binary) // #nosec G702 -- Execute the gate-selected regular binary directly, with no shell or user request arguments.
	command.Env = environment
	command.Stdout = log
	command.Stderr = log
	must(f.t, command.Start(), "start release process")
	process := &child{command: command, done: make(chan struct{}), log: log}
	f.children = append(f.children, process)
	go func() { process.err = command.Wait(); close(process.done) }()
	if kind == "worker" {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
		defer client.CloseIdleConnections()
		for _, path := range []string{"startup", "ready", "health"} {
			wait(f.t, "release worker "+path+" probe", func() bool {
				select {
				case <-process.done:
					f.t.Fatal("release worker exited before probes became available; private log: " + process.log.Name())
				default:
				}
				response, err := client.Get("http://" + address + "/v1/" + path)
				if err != nil {
					return false
				}
				defer response.Body.Close()
				var body struct {
					Data struct{ Status string }
					Meta struct{ Process string }
				}
				return json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body) == nil && response.StatusCode == http.StatusOK && body.Data.Status == "ok" && body.Meta.Process == "worker"
			})
		}
	}
	return process
}

func wait(t *testing.T, stage string, condition func() bool) {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("timed out waiting for " + stage)
		case <-tick.C:
		}
	}
}

func (f *fixture) waitBlocked(observer *pgx.Conn, label, table string) {
	f.t.Helper()
	wait(f.t, "owned process database lock", func() bool {
		var blocked bool
		err := observer.QueryRow(f.t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND position($2 in lower(query))>0)`, f.schema+"_"+label, table).Scan(&blocked)
		must(f.t, err, "observe database barrier")
		return blocked
	})
}

func (p *child) signal(t *testing.T) {
	t.Helper()
	must(t, p.command.Process.Signal(syscall.SIGTERM), "send SIGTERM")
}
func (p *child) exit(t *testing.T, want int) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		t.Fatal("release process did not exit within shutdown budget")
	}
	if p.command.ProcessState.ExitCode() != want {
		t.Fatalf("process exit=%d, want %d; private log: %s", p.command.ProcessState.ExitCode(), want, p.log.Name())
	}
}

func (f *fixture) api(label, budget string) (*child, string) {
	f.t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(f.t, err, "reserve local API address")
	address := listener.Addr().String()
	must(f.t, listener.Close(), "release local API address")
	process := f.start("api", label, budget, address)
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	wait(f.t, "release API readiness", func() bool {
		select {
		case <-process.done:
			f.t.Fatal("release API exited during startup; private log: " + process.log.Name())
		default:
		}
		response, err := client.Get("http://" + address + "/v1/ready")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode == http.StatusOK
	})
	versionResponse, err := client.Get("http://" + address + "/v1/version")
	must(f.t, err, "read release build identity")
	defer versionResponse.Body.Close()
	var identity struct {
		Data struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		}
	}
	must(f.t, json.NewDecoder(versionResponse.Body).Decode(&identity), "decode release build identity")
	if identity.Data.Version == "dev" || identity.Data.Version == "" || identity.Data.Commit != os.Getenv("EVYDENCE_LIFECYCLE_EXPECTED_COMMIT") {
		f.t.Fatal("binary build identity does not match the requested source commit")
	}
	return process, "http://" + address
}

func (f *fixture) writerExcluded() {
	f.t.Helper()
	store, err := postgres.Open(f.t.Context(), f.databaseURL)
	must(f.t, err, "open writer exclusion probe")
	defer store.Close()
	release, err := store.AcquireAPIWriterLease(f.t.Context())
	if err == nil {
		_ = release(f.t.Context())
		f.t.Fatal("another writer acquired the lease before process exit")
	}
	if !strings.Contains(err.Error(), "already active") {
		f.t.Fatal("writer probe failed for an unrelated reason")
	}
}

type response struct {
	status int
	body   []byte
	err    error
}

func (f *fixture) project(base string) response {
	request, err := http.NewRequestWithContext(f.t.Context(), http.MethodPost, base+"/v1/projects", strings.NewReader(`{"product_id":"product","name":"Lifecycle project"}`))
	if err != nil {
		return response{err: err}
	}
	request.Header.Set("Authorization", "Bearer "+f.secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "lifecycle-project")
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	result, err := client.Do(request)
	if err != nil {
		return response{err: err}
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, 1<<20))
	return response{status: result.StatusCode, body: body, err: err}
}

func (f *fixture) receipt(fields map[string]any) {
	f.t.Helper()
	if _, _, err := f.store.LoadState(f.t.Context()); err == nil {
		f.t.Fatal("runtime replaced aggregate canary")
	}
	fields["schema_version"] = "evydence-lifecycle-case.v1.0.0"
	fields["case"] = f.t.Name()
	fields["status"] = "passed"
	data, err := json.MarshalIndent(fields, "", "  ")
	must(f.t, err, "encode case receipt")
	must(f.t, os.WriteFile(filepath.Join(f.artifactDir, "receipt.json"), data, 0600), "write case receipt")
}

func sameJSON(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func TestReleaseBinaryAPIGraceful(t *testing.T) { testAPI(t, false) }
func TestReleaseBinaryAPIForced(t *testing.T)   { testAPI(t, true) }
func testAPI(t *testing.T, forced bool) {
	f := newFixture(t)
	budget := "5"
	if forced {
		budget = "1"
	}
	api, base := f.api("initial", budget)
	lock, err := f.conn.Begin(t.Context())
	must(t, err, "begin API barrier")
	f.locks = append(f.locks, lock)
	_, err = lock.Exec(t.Context(), `SELECT 1 FROM products WHERE id='product' FOR UPDATE`)
	must(t, err, "hold API parent row")
	result := make(chan response, 1)
	f.requests.Add(1)
	go func() { defer f.requests.Done(); result <- f.project(base) }()
	// Use a separate connection because f.conn owns the barrier transaction.
	probe, err := pgx.Connect(t.Context(), f.databaseURL)
	must(t, err, "open API barrier observer")
	defer probe.Close(context.WithoutCancel(t.Context()))
	f.waitBlocked(probe, "initial", "products")
	f.writerExcluded()
	api.signal(t)
	if forced {
		api.exit(t, 1)
	} else {
		wait(t, "API admission stopped", func() bool {
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(base, "http://"), 100*time.Millisecond)
			if err != nil {
				return true
			}
			_ = conn.Close()
			return false
		})
		f.writerExcluded()
	}
	must(t, lock.Rollback(t.Context()), "release API barrier")
	if !forced {
		api.exit(t, 0)
	}
	var first response
	select {
	case first = <-result:
	case <-time.After(8 * time.Second):
		t.Fatal("admitted API request did not finish")
	}
	if !forced && (first.err != nil || first.status != http.StatusCreated) {
		t.Fatal("graceful mutation did not complete", first.status)
	}
	if forced && first.err == nil && first.status < 400 {
		t.Fatal("forced mutation returned success")
	}
	var before int
	must(t, f.conn.QueryRow(t.Context(), `SELECT count(*) FROM projects`).Scan(&before), "read post-exit project count")
	want := 1
	if forced {
		want = 0
	}
	if before != want {
		t.Fatal("API durable state after stop", before, want)
	}
	restarted, retryBase := f.api("restarted", "5")
	replayed := f.project(retryBase)
	if replayed.err != nil || replayed.status != http.StatusCreated {
		t.Fatal("restart retry failed", replayed.status)
	}
	again := f.project(retryBase)
	if !sameJSON(replayed.body, again.body) {
		must(t, os.WriteFile(filepath.Join(f.artifactDir, "project-first.json"), replayed.body, 0600), "record first retry response")
		must(t, os.WriteFile(filepath.Join(f.artifactDir, "project-again.json"), again.body, 0600), "record replay response")
	}
	if again.err != nil || again.status != http.StatusCreated || !sameJSON(replayed.body, again.body) {
		t.Fatal("restart replay was not stable")
	}
	var projects, audits, receipts int
	must(t, f.conn.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM projects),(SELECT count(*) FROM audit_chain_entries WHERE entry_type='project.created'),(SELECT count(*) FROM idempotency_records WHERE state='completed')`).Scan(&projects, &audits, &receipts), "count durable API effects")
	if projects != 1 || audits != 1 || receipts != 1 {
		t.Fatal("API retry duplicated or lost effects", projects, audits, receipts)
	}
	restarted.signal(t)
	restarted.exit(t, 0)
	f.receipt(map[string]any{"process": "api", "forced": forced, "initial_exit_code": api.command.ProcessState.ExitCode(), "restart_exit_code": restarted.command.ProcessState.ExitCode(), "projects": projects, "project_audit_entries": audits, "completed_idempotency_records": receipts, "post_stop_projects": before, "database_lock_barrier": true, "writer_exclusion_during_work": true})
}

func TestReleaseBinaryWorkerGraceful(t *testing.T) { testWorker(t, false) }
func TestReleaseBinaryWorkerForced(t *testing.T)   { testWorker(t, true) }
func testWorker(t *testing.T, forced bool) {
	f := newFixture(t)
	objects, err := filesystem.New(f.objects)
	must(t, err, "open fixture objects")
	data := []byte("lifecycle-payload-fixture")
	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])
	digest := "sha256:" + hexHash
	now := time.Now().UTC()
	payload := app.ObjectPayload{TenantID: f.tenant, Digest: digest, Size: int64(len(data)), MediaType: "text/plain", StagingKey: "tenants/" + f.tenant + "/staging/sha256/" + hexHash, FinalKey: "tenants/" + f.tenant + "/payloads/sha256/" + hexHash, Status: app.ObjectPayloadStaged, CreatedAt: now, UpdatedAt: now}
	payload, err = objects.StagePayload(t.Context(), payload, bytes.NewReader(data))
	must(t, err, "stage native payload")
	uow, err := f.store.BeginUnitOfWork(t.Context())
	must(t, err, "begin native payload metadata")
	defer func() { _ = uow.Rollback(context.WithoutCancel(t.Context())) }()
	must(t, uow.Repositories().Payloads.RecordStagedObjectPayload(t.Context(), payload), "record staged metadata")
	must(t, uow.Commit(t.Context()), "commit staged metadata")
	must(t, f.store.Enqueue(t.Context(), app.OutboxJob{ID: "lifecycle-job", TenantID: f.tenant, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, Payload: map[string]any{"payload_digest": digest}, CreatedAt: now}), "enqueue native job")
	lock, err := f.conn.Begin(t.Context())
	must(t, err, "begin worker barrier")
	f.locks = append(f.locks, lock)
	_, err = lock.Exec(t.Context(), `SELECT 1 FROM object_payloads WHERE tenant_id=$1 AND digest=$2 FOR UPDATE`, f.tenant, digest)
	must(t, err, "hold payload metadata row")
	budget := "5"
	if forced {
		budget = "1"
	}
	worker := f.start("worker", "worker", budget, "")
	probe, err := pgx.Connect(t.Context(), f.databaseURL)
	must(t, err, "open worker barrier observer")
	defer probe.Close(context.WithoutCancel(t.Context()))
	f.waitBlocked(probe, "worker", "object_payloads")
	worker.signal(t)
	if !forced {
		wait(t, "worker drain status", func() bool {
			data, err := os.ReadFile(worker.log.Name())
			must(t, err, "read worker drain status")
			for _, line := range bytes.Split(data, []byte("\n")) {
				var event struct {
					Service string `json:"service"`
					Event   string `json:"msg"`
					Result  string `json:"result_code"`
				}
				if json.Unmarshal(line, &event) == nil && event.Service == "worker" && event.Event == "drain" && event.Result == "started" {
					return true
				}
			}
			return false
		})
	}
	if forced {
		worker.exit(t, 1)
	}
	must(t, lock.Rollback(t.Context()), "release worker barrier")
	if !forced {
		worker.exit(t, 0)
	}
	var status, oldLease string
	var attempts int
	must(t, f.conn.QueryRow(t.Context(), `SELECT status,attempts,coalesce(lease_token,'') FROM outbox_jobs WHERE id='lifecycle-job'`).Scan(&status, &attempts, &oldLease), "read stopped job")
	var restartExit any
	if forced {
		if status != "running" || attempts != 1 || oldLease == "" {
			t.Fatal("forced worker falsely acknowledged job", status, attempts)
		}
		var outcomes int
		must(t, f.conn.QueryRow(t.Context(), `SELECT count(*) FROM outbox_job_attempts WHERE outcome<>'claimed'`).Scan(&outcomes), "read unfinished job history")
		if outcomes != 0 {
			t.Fatal("forced worker recorded a false outcome", outcomes)
		}
		_, err = f.conn.Exec(t.Context(), `UPDATE outbox_jobs SET locked_at=now()-interval '6 minutes' WHERE id='lifecycle-job'`)
		must(t, err, "advance isolated fixture lease expiry")
		// A disconnected finalization transaction may already have committed.
		// Block acknowledgment instead, so both uncertain-commit outcomes must
		// acquire a new lease and reject the old token before completing once.
		barrierKey := time.Now().UnixNano()
		_, err = f.conn.Exec(t.Context(), fmt.Sprintf(`
			CREATE FUNCTION lifecycle_completion_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.id='lifecycle-job' AND NEW.status='succeeded' AND NEW.attempts=2 THEN
					PERFORM pg_advisory_xact_lock(%d);
				END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER lifecycle_completion_barrier BEFORE UPDATE ON outbox_jobs
			FOR EACH ROW EXECUTE FUNCTION lifecycle_completion_barrier()`, barrierKey))
		must(t, err, "install isolated retry completion barrier")
		retryBarrier, err := f.conn.Begin(t.Context())
		must(t, err, "begin retry fencing barrier")
		f.locks = append(f.locks, retryBarrier)
		_, err = retryBarrier.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, barrierKey)
		must(t, err, "hold retry completion lock")
		retry := f.start("worker", "worker-retry", "5", "")
		f.waitBlocked(probe, "worker-retry", "outbox_jobs")
		var currentLease string
		must(t, probe.QueryRow(t.Context(), `SELECT status,attempts,lease_token FROM outbox_jobs WHERE id='lifecycle-job'`).Scan(&status, &attempts, &currentLease), "read replacement lease")
		if status != "running" || attempts != 2 || currentLease == oldLease || currentLease == "" {
			t.Fatal("replacement process did not acquire a fresh live lease")
		}
		fenceContext, cancelFence := context.WithTimeout(t.Context(), time.Second)
		err = f.store.CompleteJob(fenceContext, "lifecycle-job", oldLease)
		cancelFence()
		if !errors.Is(err, app.ErrConflict) {
			t.Fatal("stale lease acknowledged running retry", err)
		}
		must(t, retryBarrier.Rollback(t.Context()), "release retry fencing barrier")
		wait(t, "retry completion", func() bool {
			must(t, f.conn.QueryRow(t.Context(), `SELECT status,attempts FROM outbox_jobs WHERE id='lifecycle-job'`).Scan(&status, &attempts), "observe retry")
			return status == "succeeded"
		})
		retry.signal(t)
		retry.exit(t, 0)
		restartExit = retry.command.ProcessState.ExitCode()
	}
	wantAttempts := 1
	if forced {
		wantAttempts = 2
	}
	if status != "succeeded" || attempts != wantAttempts {
		t.Fatal("worker did not complete once after drain/retry", status, attempts)
	}
	var successes, failures, payloads int
	must(t, f.conn.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM outbox_job_attempts WHERE outcome='succeeded'),(SELECT count(*) FROM outbox_job_attempts WHERE outcome IN('retrying','dead_letter')),(SELECT count(*) FROM object_payloads WHERE status='finalized')`).Scan(&successes, &failures, &payloads), "count worker effects")
	if successes != 1 || failures != 0 || payloads != 1 {
		t.Fatal("worker replay duplicated or lost effects", successes, failures, payloads)
	}
	final, err := objects.GetBounded(t.Context(), payload.FinalKey, int64(len(data)))
	must(t, err, "verify finalized object")
	if !bytes.Equal(final.Bytes, data) {
		t.Fatal("retry changed payload bytes")
	}
	f.receipt(map[string]any{"process": "worker", "forced": forced, "initial_exit_code": worker.command.ProcessState.ExitCode(), "restart_exit_code": restartExit, "attempts": attempts, "success_outcomes": successes, "failure_outcomes": failures, "finalized_payloads": payloads, "database_lock_barrier": true, "payload_digest": digest})
}
