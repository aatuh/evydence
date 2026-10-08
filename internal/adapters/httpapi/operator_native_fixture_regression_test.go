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

func TestOperatorNativeFixturesSelectCommittedCountsWithoutAggregatePublication(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*", app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	// Write through repositories only. Neither creation facade nor cache
	// publication is invoked. Readers must return these new authoritative rows.
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	err = ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.Evidence.InsertEvidence(ctx, domain.EvidenceItem{ID: "repository-only", TenantID: actor.TenantID, Type: "security_review", Title: "private-evidence-title", PayloadHash: "sha256:" + strings.Repeat("a", 64), CanonicalHash: "sha256:" + strings.Repeat("b", 64), CreatedAt: at}); err != nil {
			return err
		}
		return r.Identity.InsertHumanUser(ctx, domain.HumanUser{ID: "repository-user", TenantID: actor.TenantID, Email: "private-user@example.test", DisplayName: "Private User", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: at})
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: actor}})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(operatorFixtureResources{now: func() time.Time { return at }})
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	metrics := getRaw(t, server, "fixture", "/v1/metrics", http.StatusOK)
	if dataMap(t, metrics.Body.String())["resource_counts"].(map[string]any)["evidence"] != float64(1) {
		t.Fatal("native metrics consulted stale aggregate evidence", metrics.Body.String())
	}
	instance := getRaw(t, server, "fixture", "/v1/admin/instance", http.StatusOK)
	counts := dataMap(t, instance.Body.String())["resource_counts"].(map[string]any)
	if counts["evidence"] != float64(1) || counts["users"] != float64(1) || dataField(t, instance.Body.String(), "generated_at") != at.Format(time.RFC3339) {
		t.Fatal("native instance counts consulted stale aggregate rows or clock", instance.Body.String())
	}
	for _, private := range []string{"private-evidence-title", "private-user@example.test", "repository-only", "repository-user"} {
		if strings.Contains(metrics.Body.String(), private) || strings.Contains(instance.Body.String(), private) {
			t.Fatal("scalar query exposed entity metadata", private)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native count read wrote repository state", err)
	}
}

type operatorQueryFailureFactory struct {
	base      *app.MemoryUnitOfWorkFactory
	fail      bool
	rollbacks int
}
type operatorQueryFailureTransaction struct {
	app.UnitOfWork
	factory *operatorQueryFailureFactory
}

func (f *operatorQueryFailureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	u, err := f.base.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return operatorQueryFailureTransaction{u, f}, nil
}
func (u operatorQueryFailureTransaction) Commit(ctx context.Context) error {
	if u.factory.fail {
		return errors.New("private-query-commit-secret")
	}
	return u.UnitOfWork.Commit(ctx)
}
func (u operatorQueryFailureTransaction) Rollback(ctx context.Context) error {
	u.factory.rollbacks++
	return u.UnitOfWork.Rollback(ctx)
}

func TestOperatorNativeQueriesDiscardCompleteProjectionOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	actor := owner.actor
	actor.Scopes = []string{"*", app.ScopeInstanceAdmin}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: actor}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	for _, path := range []string{"/v1/metrics", "/v1/admin/instance"} {
		rollbacks := factory.rollbacks
		body := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
		if factory.rollbacks != rollbacks+1 || strings.Contains(body, "private-query") || strings.Contains(body, "resource_counts") || strings.Contains(body, owner.evidence.ID) {
			t.Fatal("query commit failure exposed projection or did not release transaction", body)
		}
	}
	v, err := server.metricsQuery.Snapshot(t.Context(), actor)
	if err == nil || v != nil {
		t.Fatal("failed native metrics returned partial data", v, err)
	}
	snapshot, err := server.instanceAdminQuery.Snapshot(t.Context(), actor)
	if err == nil || snapshot.ResourceCounts != nil || snapshot.ReportType != "" {
		t.Fatal("failed native instance query returned partial data", snapshot, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed count queries committed any state", err)
	}
}

func TestOperatorNativeResourceBindingKeepsExplicitResourcesAcrossRebinding(t *testing.T) {
	first := newLegacyLedgerFixture(app.Config{UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server, err := newLegacyServerFixture(first)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	operator := &fakeOutboxAdminHTTP{diag: app.OutboxDiagnostics{TerminalJobs: 3}}
	checks := []operationsquery.ReadinessCheck{{Name: "postgres", FailureDetail: "safe failure", Check: func(context.Context) error { return errors.New("private-probe") }}}
	server.bindOperatorFixtureResources(operatorFixtureResources{checks: checks, operator: operator, now: func() time.Time { return at }})
	checks[0].Name, checks[0].FailureDetail = "modified", "private-modification"
	second := newLegacyLedgerFixture(app.Config{UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server.bindLegacyLedgerFixture(second)
	ports := []operatorFixtureQueries{
		server.readinessQuery.(readinessFixture).operatorFixtureQueries,
		server.metricsQuery.(metricsFixture).operatorFixtureQueries,
		server.instanceAdminQuery.(instanceAdminFixture).operatorFixtureQueries,
		server.outboxDiagnosticsQuery.(outboxDiagnosticsFixture).operatorFixtureQueries,
		server.outboxReplayCommand.(outboxReplayFixture).operatorFixtureQueries,
	}
	for _, port := range ports {
		if port.ledger != second || port.resources.operator != operator || port.now() != at || port.resources.checks[0].Name != "postgres" || port.resources.checks[0].FailureDetail != "safe failure" {
			t.Fatal("rebind discarded resources or retained caller's mutable checks")
		}
	}
	actor := domain.Actor{TenantID: "operator", KeyID: "instance", Scopes: []string{app.ScopeInstanceAdmin}}
	public, err := server.readinessQuery.Public(t.Context())
	encoded, marshalErr := json.Marshal(public)
	if err != nil || marshalErr != nil || public["status"] != "unavailable" || strings.Contains(string(encoded), "private") {
		t.Fatal("rebound native readiness lost probe/redaction", public, err, marshalErr)
	}
	counts, err := server.outboxDiagnosticsQuery.Diagnostics(t.Context(), actor)
	if err != nil || counts.TerminalJobs != 3 {
		t.Fatal("rebound native diagnostics lost configured operator", counts, err)
	}
}

func TestOperatorNativeReplayValidatesOperatorResultBeforeSavingSuccess(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Instance", "admin", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	operator := &recordingReplayFixtureOperator{fakeOutboxAdminHTTP: fakeOutboxAdminHTTP{replay: app.OutboxReplay{JobID: "wrong-job", Status: "queued", ReplayedAt: time.Now().UTC()}}}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: actor}})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(operatorFixtureResources{operator: operator})
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body := postRaw(t, server, "fixture", "/v1/admin/outbox/job_terminal/replay", "bad-result", []byte("{}"), http.StatusBadRequest)
	if operator.calls != 1 || strings.Contains(body, "wrong-job") || strings.Contains(body, "replayed_at") {
		t.Fatal("focused replay accepted or exposed invalid operator feedback", body)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("failed replay lost failure receipt", err)
	}
	for k, v := range after.Idempotency {
		if _, exists := before.Idempotency[k]; !exists && (v.State != app.IdempotencyFailed || v.Status != 0 || v.Response != nil) {
			t.Fatal("invalid operator result saved partial success")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid operator result changed repository/audit state")
	}
	// The fake was genuinely called; its external side effect is not asserted
	// to have rolled back. Durable replay/audit atomicity needs the SQL adapter.
}

type operatorNativeReconciliationFixture struct {
	tenant  string
	calls   int
	metrics app.ObjectReconciliationMetrics
}

func (f *operatorNativeReconciliationFixture) ObjectReconciliationMetrics(ctx context.Context, tenant string) (app.ObjectReconciliationMetrics, error) {
	if err := ctx.Err(); err != nil {
		return app.ObjectReconciliationMetrics{}, err
	}
	f.tenant, f.calls = tenant, f.calls+1
	return f.metrics, nil
}

func TestOperatorNativeMetricsUseTenantBoundExplicitReconciliationResource(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	receipts := &operatorNativeReconciliationFixture{metrics: app.ObjectReconciliationMetrics{Runs: 2, ScannedPayloads: 3, MissingFinalObjects: 4, MissingStagedObjects: 5, DigestMismatches: 6, ProviderOrphans: 7, QuarantinedPayloads: 8, LastRunAt: at.Add(-30 * time.Second)}}
	auth := &configuredAuthenticator{actor: owner.actor}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.bindOperatorFixtureResources(operatorFixtureResources{reconciliation: receipts, now: func() time.Time { return at }})
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	out := getRaw(t, server, "fixture", "/v1/metrics", http.StatusOK).Body.String()
	data := dataMap(t, out)
	for k, v := range map[string]float64{"object_reconciliation_runs": 2, "object_reconciliation_scanned_payloads": 3, "object_reconciliation_missing_final_objects": 4, "object_reconciliation_missing_staged_objects": 5, "object_reconciliation_digest_mismatches": 6, "object_reconciliation_provider_orphans": 7, "object_reconciliation_quarantined_payloads": 8, "object_reconciliation_last_run_age_seconds": 30} {
		if data[k] != v {
			t.Fatal("native metrics lost explicit receipt counter or deterministic age", k, data[k])
		}
	}
	if receipts.tenant != owner.actor.TenantID || receipts.calls != 1 || strings.Contains(out, "outbox_") {
		t.Fatal("receipt reads were not tenant-bound or leaked global queue counters", out)
	}
	auth.actor.Scopes = nil
	getRaw(t, server, "fixture", "/v1/metrics", http.StatusForbidden)
	if receipts.calls != 1 {
		t.Fatal("denied metric request reached receipt adapter")
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("explicit receipt read changed repository state", err)
	}
}
