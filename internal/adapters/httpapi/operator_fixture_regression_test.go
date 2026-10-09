package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestOperatorQueryFixturesPreserveResponsesIsolationAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	operator := &fakeOutboxAdminHTTP{diag: app.OutboxDiagnostics{PendingJobs: 2, RunningJobs: 1, TerminalJobs: 3, OldestPendingCreatedAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}}
	resources := operatorFixtureResources{
		now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }, operator: operator,
		checks: []operationsquery.ReadinessCheck{{Name: "postgres", FailureDetail: "database connectivity is unavailable", Check: func(context.Context) error { return errors.New("private-probe-secret@database.internal") }}},
	}
	ledger := newLegacyLedgerFixture(app.Config{
		APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: resources.now,
	})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	if _, err := ledger.CreateEvidence(t.Context(), foreign.actor, app.CreateEvidenceInput{ProductID: foreign.product.ID, ReleaseID: foreign.release.ID, Type: "security_review", Title: "private-foreign-title", PayloadHash: "sha256:" + strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	instance := owner.actor
	instance.Scopes = []string{"*", app.ScopeInstanceAdmin}
	auth := &configuredAuthenticator{actor: instance}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(resources)
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// Independent complete DTO expectations include the focused runtime's
	// explicit zero reconciliation counters, not the removed aggregate API.
	metrics := map[string]any{
		"tenant_id":                           instance.TenantID,
		"resource_counts":                     map[string]int{"audit_chain_entries": len(before.AuditEntries[instance.TenantID]), "artifact_signatures": 0, "cosign_verifications": 0, "evidence": 1, "merkle_batches": 0, "object_retention_policies": 0, "release_bundles": 0, "transparency_checkpoints": 0},
		"customer_portal_failed_access_count": 0, "customer_portal_revoked_access_count": 0,
		"object_reconciliation_runs": int64(0), "object_reconciliation_scanned_payloads": int64(0),
		"object_reconciliation_missing_final_objects": int64(0), "object_reconciliation_missing_staged_objects": int64(0),
		"object_reconciliation_digest_mismatches": int64(0), "object_reconciliation_provider_orphans": int64(0),
		"object_reconciliation_quarantined_payloads": int64(0), "object_reconciliation_last_run_age_seconds": 0,
		"outbox_pending_jobs": 2, "outbox_running_jobs": 1, "outbox_terminal_jobs": 3, "outbox_oldest_pending_age_seconds": 0,
	}
	snapshot := domain.InstanceAdminSnapshot{ReportType: "instance_admin_snapshot", TenantCount: 2,
		ResourceCounts: map[string]int{"tenants": 2, "users": 0, "collectors": 0, "evidence": 3},
		Limitations:    []string{"Instance admin diagnostics expose operational counts only and not raw evidence payloads or secrets."}, GeneratedAt: resources.now()}
	diagnostics := map[string]any{"status": "unavailable", "checks": []map[string]string{{"name": "ledger", "status": "ok"}, {"name": "postgres", "status": "unavailable", "detail": "database connectivity is unavailable"}}}
	public := map[string]any{"status": "unavailable", "checks": []map[string]string{{"name": "ledger", "status": "ok"}, {"name": "postgres", "status": "unavailable"}}}
	retry := app.DescribeProblem(app.ErrDependencyUnavailable)
	public["retryable"], public["retry_class"], public["retry_after_seconds"] = retry.Retryable, retry.RetryClass, retry.RetryAfterSeconds
	requests := []struct {
		path string
		code int
		want any
	}{
		{"/v1/ready", 503, public}, {"/v1/admin/readiness", 200, diagnostics},
		{"/v1/metrics", 200, metrics}, {"/v1/admin/instance", 200, snapshot},
		{"/v1/admin/outbox", 200, operator.diag},
	}
	for _, request := range requests {
		out := getRaw(t, server, "fixture-auth", request.path, request.code)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out.Body.String())
		if request.path == "/v1/ready" && out.Header().Get("Retry-After") != "5" {
			t.Fatal("public readiness lost retry metadata")
		}
		for _, private := range []string{"private-probe-secret", "database.internal", "private-foreign-title", foreign.actor.TenantID, foreign.evidence.ID} {
			if strings.Contains(out.Body.String(), private) {
				t.Fatal("operator query exposed private material", request.path, private)
			}
		}
	}
	plain := getRawWithAccept(t, server, "fixture-auth", "/v1/metrics", "text/plain", 200)
	if plain.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || plain.Body.String() != prometheusMetrics(metrics) {
		t.Fatal("complete Prometheus response changed", plain.Body.String())
	}
	base := operatorFixtureQueries{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, resources: resources}
	projected, err := (instanceAdminFixture{base}).Snapshot(t.Context(), instance)
	if err != nil {
		t.Fatal(err)
	}
	projected.ResourceCounts["evidence"], projected.Limitations[0] = -1, "modified"
	projectedMetrics, err := (metricsFixture{base}).Snapshot(t.Context(), instance)
	if err != nil {
		t.Fatal(err)
	}
	projectedMetrics["resource_counts"].(map[string]int)["evidence"] = -1
	projectedReadiness, err := (readinessFixture{base}).Operator(t.Context(), instance)
	if err != nil {
		t.Fatal(err)
	}
	projectedReadiness["checks"].([]map[string]string)[1]["detail"] = "modified"
	for _, request := range requests {
		out := getRaw(t, server, "fixture-auth", request.path, request.code)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out.Body.String())
	}
	// Tenant wildcard authority cannot expose instance diagnostics, including
	// after a preceding successful instance-admin request.
	auth.actor = owner.actor
	for _, path := range []string{"/v1/admin/readiness", "/v1/admin/instance", "/v1/admin/outbox"} {
		getRaw(t, server, "fixture-auth", path, 403)
		auth.err = app.ErrUnauthorized
		getRawNoAuth(t, server, path, 401)
		auth.err = nil
	}
	tenantMetrics := getRaw(t, server, "fixture-auth", "/v1/metrics", 200)
	if strings.Contains(tenantMetrics.Body.String(), "outbox_") || dataMap(t, tenantMetrics.Body.String())["resource_counts"].(map[string]any)["evidence"] != float64(1) {
		t.Fatal("tenant metrics leaked global queue counts", tenantMetrics.Body.String())
	}
	if text := getRawWithAccept(t, server, "fixture-auth", "/v1/metrics", "text/plain", 200).Body.String(); strings.Contains(text, "outbox_") || strings.Contains(text, "tenant_id") || strings.Contains(text, owner.actor.TenantID) {
		t.Fatal("tenant Prometheus metrics exposed instance data or tenant labels", text)
	}
	auth.actor = foreign.actor
	if dataMap(t, getRaw(t, server, "fixture-auth", "/v1/metrics", 200).Body.String())["resource_counts"].(map[string]any)["evidence"] != float64(2) {
		t.Fatal("second tenant did not receive its own counts")
	}
	auth.actor.Scopes = nil
	getRaw(t, server, "fixture-auth", "/v1/metrics", 403)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, read := range map[string]func() error{
		"public":   func() error { _, err := (readinessFixture{base}).Public(ctx); return err },
		"operator": func() error { _, err := (readinessFixture{base}).Operator(ctx, instance); return err },
		"metrics":  func() error { _, err := (metricsFixture{base}).Snapshot(ctx, instance); return err },
		"instance": func() error { _, err := (instanceAdminFixture{base}).Snapshot(ctx, instance); return err },
		"outbox":   func() error { _, err := (outboxDiagnosticsFixture{base}).Diagnostics(ctx, instance); return err },
	} {
		if err := read(); !errors.Is(err, context.Canceled) {
			t.Fatal("query ignored cancellation", name, err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("operator query/authorization/cancellation changed stored state", err)
	}
}

type recordingReplayFixtureOperator struct {
	fakeOutboxAdminHTTP
	calls int
}

func (f *recordingReplayFixtureOperator) ReplayTerminalJob(ctx context.Context, jobID, actorID string) (app.OutboxReplay, error) {
	f.calls++
	return f.fakeOutboxAdminHTTP.ReplayTerminalJob(ctx, jobID, actorID)
}

func TestOperatorReplayFixtureRechecksAuthorityAndDoesNotRepeatOperatorEffect(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	operator := &recordingReplayFixtureOperator{fakeOutboxAdminHTTP: fakeOutboxAdminHTTP{replay: app.OutboxReplay{JobID: "job_terminal", Status: "queued", ReplayedAt: at}}}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, OutboxAdmin: operator, Now: func() time.Time { return at }})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	auth := &configuredAuthenticator{actor: instance}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(operatorFixtureResources{operator: operator, now: func() time.Time { return at }})
	path := "/v1/admin/outbox/job_terminal/replay"
	postRaw(t, server, "fixture-auth", path, "", []byte("{}"), 400)
	postRaw(t, server, "fixture-auth", path, "oversized", []byte(strings.Repeat("x", int(app.SmallJSONRequestLimit)+1)), 400)
	if operator.calls != 0 {
		t.Fatal("invalid replay reached the operator")
	}
	first := postRaw(t, server, "fixture-auth", path, "same-key", []byte("{}"), 200)
	want, err := json.Marshal(map[string]any{"data": operator.replay, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), first)
	before, err := factory.Snapshot()
	if err != nil || len(before.Idempotency) != 1 || operator.calls != 1 || operator.actor != instance.KeyID {
		t.Fatal("fixture did not commit one safe replay receipt/operator call", err)
	}
	replayed := postRaw(t, server, "fixture-auth", path, "same-key", []byte("{}"), 200)
	assertTrustHTTPReplay(t, first, replayed)
	postRaw(t, server, "fixture-auth", path, "same-key", []byte("{ }"), 409)
	auth.actor.Scopes = []string{"*"}
	postRaw(t, server, "fixture-auth", path, "same-key", []byte("{}"), 403)
	postRaw(t, server, "fixture-auth", path, "new-key", []byte("{}"), 403)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := server.outboxReplayCommand.ReplayIdempotent(ctx, instance, http.MethodPost, path, "cancelled", []byte("{}"), operator.replay.JobID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled replay reached the operator", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || operator.calls != 1 {
		t.Fatal("repeat/conflict/revocation/cancellation changed receipt state or repeated the operator effect", err, operator.calls)
	}
}

func TestOperatorFixtureBindingPreservesExplicitFocusedPorts(t *testing.T) {
	readiness := &struct{ ReadinessQuery }{}
	metrics := &struct{ MetricsQuery }{}
	instance := &struct{ InstanceAdminQuery }{}
	diagnostics := &struct{ OutboxDiagnosticsQuery }{}
	replay := &struct{ OutboxReplayCommand }{}
	server, err := newLegacyServerFixtureWithOptions(newLegacyLedgerFixture(app.Config{}), ServerOptions{
		ReadinessQuery: readiness, MetricsQuery: metrics, InstanceAdminQuery: instance,
		OutboxDiagnosticsQuery: diagnostics, OutboxReplayCommand: replay,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(operatorFixtureResources{checks: []operationsquery.ReadinessCheck{{Name: "explicit", Check: func(context.Context) error { return nil }}}})
	server.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if server.readinessQuery != readiness || server.metricsQuery != metrics || server.instanceAdminQuery != instance || server.outboxDiagnosticsQuery != diagnostics || server.outboxReplayCommand != replay {
		t.Fatal("fixture binding replaced an explicitly configured focused port")
	}
}
