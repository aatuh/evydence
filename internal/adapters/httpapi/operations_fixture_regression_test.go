package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type failingOperationsFixture struct {
	operationsFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingOperationsFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private operations failure after write")
}
func (f *failingOperationsFixture) CreateIncident(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentInput) (operationsdomain.Incident, error) {
	v, err := f.operationsFixtureCommands.CreateIncident(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingOperationsFixture) RecordIncidentTimelineEvent(ctx context.Context, a domain.Actor, id string, in operationsapp.RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error) {
	v, err := f.operationsFixtureCommands.RecordIncidentTimelineEvent(ctx, a, id, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingOperationsFixture) CreateRemediationTask(ctx context.Context, a domain.Actor, in operationsapp.CreateRemediationTaskInput) (operationsdomain.RemediationTask, error) {
	v, err := f.operationsFixtureCommands.CreateRemediationTask(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingOperationsFixture) CreateIncidentWebhookReceiver(ctx context.Context, a domain.Actor, in operationsapp.CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error) {
	v, err := f.operationsFixtureCommands.CreateIncidentWebhookReceiver(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingOperationsFixture) CreateLegalHold(ctx context.Context, a domain.Actor, in operationsapp.RetentionMarkerInput) (operationsdomain.LegalHold, error) {
	v, err := f.operationsFixtureCommands.CreateLegalHold(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingOperationsFixture) CreateRetentionOverride(ctx context.Context, a domain.Actor, in operationsapp.RetentionOverrideInput) (operationsdomain.RetentionOverride, error) {
	v, err := f.operationsFixtureCommands.CreateRetentionOverride(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}

type operationsFixtureScope struct {
	actor    domain.Actor
	product  domain.Product
	release  domain.Release
	evidence domain.EvidenceItem
	incident domain.Incident
}

func callFixtureSignedWebhook(t *testing.T, server *Server, receiver string, private ed25519.PrivateKey, at time.Time, event string, body []byte, want int) string {
	t.Helper()
	signature := ed25519.Sign(private, operationsapp.IncidentWebhookSignedPayload(at, event, body))
	r := httptest.NewRequest("POST", "/v1/incident-webhooks/"+receiver, strings.NewReader(string(body))).WithContext(t.Context())
	r.Header.Set("X-Evydence-Webhook-Event-ID", event)
	r.Header.Set("X-Evydence-Webhook-Timestamp", at.Format(time.RFC3339Nano))
	r.Header.Set("X-Evydence-Webhook-Signature", "ed25519="+base64.RawStdEncoding.EncodeToString(signature))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != want || strings.Contains(w.Body.String(), "private webhook") || strings.Contains(w.Body.String(), base64.RawStdEncoding.EncodeToString(private)) || strings.Contains(w.Body.String(), base64.RawStdEncoding.EncodeToString(signature)) {
		t.Fatal("unsafe signed callback response", w.Code, want, w.Body.String())
	}
	return w.Body.String()
}

func seedOperationsFixtureScope(t *testing.T, ledger *app.Ledger, name string) operationsFixtureScope {
	t.Helper()
	var f operationsFixtureScope
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	f.actor, err = ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	f.product, err = ledger.CreateProduct(t.Context(), f.actor, name, strings.ToLower(name))
	if err != nil {
		t.Fatal(err)
	}
	f.release, err = ledger.CreateRelease(t.Context(), f.actor, f.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	f.evidence, err = ledger.CreateEvidence(t.Context(), f.actor, app.CreateEvidenceInput{ProductID: f.product.ID, ReleaseID: f.release.ID, Type: "security_review", Title: "Review", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	f.incident, err = ledger.CreateIncident(t.Context(), f.actor, app.CreateIncidentInput{ProductID: f.product.ID, ReleaseID: f.release.ID, Title: "Initial incident", Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type operationsFixtureRequest struct{ name, path, body string }

func operationsFixtureRequests(f operationsFixtureScope) []operationsFixtureRequest {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	public := base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	return []operationsFixtureRequest{
		{"incident", "/v1/incidents", fmt.Sprintf(`{"product_id":%q,"release_id":%q,"title":"New incident","severity":"critical"}`, f.product.ID, f.release.ID)},
		{"timeline", "/v1/incidents/" + f.incident.ID + "/timeline", fmt.Sprintf(`{"event_type":"noted","summary":"Containment recorded","evidence_id":%q}`, f.evidence.ID)},
		{"task", "/v1/remediation-tasks", fmt.Sprintf(`{"incident_id":%q,"release_id":%q,"evidence_id":%q,"title":"Patch","owner":"Security Team","due_at":"2026-10-08T16:00:00Z"}`, f.incident.ID, f.release.ID, f.evidence.ID)},
		{"receiver", "/v1/incidents/" + f.incident.ID + "/webhook-receivers", fmt.Sprintf(`{"name":"Pager","provider":"fixture","public_key":%q}`, public)},
		{"hold", "/v1/legal-holds", fmt.Sprintf(`{"scope_type":"release","scope_id":%q,"reason":"Review","owner":"Legal Team"}`, f.release.ID)},
		{"override", "/v1/retention-overrides", fmt.Sprintf(`{"scope_type":"evidence","scope_id":%q,"reason":"Review","owner":"Security Team","retention_until":"2026-10-09T16:00:00Z"}`, f.evidence.ID)},
	}
}

func TestOperationsFixturesRollBackEveryRecordAndAuditAfterWriteFailure(t *testing.T) {
	for index := 0; index < 6; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedOperationsFixtureScope(t, ledger, "Owner")
		request := operationsFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingOperationsFixture{operationsFixtureCommands: operationsFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.incidentCommands, server.incidentWebhookCommands, server.retentionMarkerCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, "private operations") {
				t.Fatal("failed operations command bypassed isolation or leaked partial metadata")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed receipt missing", err)
			}
			for key, record := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
					t.Fatal("partial success cached")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed command committed incident, timeline, task, receiver, hold, override, audit or job effects")
			}
		})
	}
}

func TestOperationsFixturesReplayRechecksHumanGrantsAndForeignCoordinatesWithoutEffects(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"incident:write", "admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"admin"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"incident:write"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range operationsFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201))
			auth.actor.ResourceGrants = nil
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			auth.actor.TenantID = foreign.actor.TenantID
			auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"*"}}}
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 404)
			auth.actor = human
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("completed/rejected operations replay repeated effects", err)
			}
		})
	}
}

// Repository failure happens after the real two-record insert but before audit
// and commit, proving that the public callback's own unit of work rolls back.
type failingWebhookFixtureFactory struct {
	inner *app.MemoryUnitOfWorkFactory
	fail  bool
}

func (f *failingWebhookFixtureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	uow, err := f.inner.BeginUnitOfWork(ctx)
	if err != nil || !f.fail {
		return uow, err
	}
	return failingWebhookFixtureUnit{UnitOfWork: uow}, nil
}

type failingWebhookFixtureUnit struct{ app.UnitOfWork }

func (f failingWebhookFixtureUnit) Repositories() app.Repositories {
	repos := f.UnitOfWork.Repositories()
	repos.Risk = failingWebhookFixtureRecords{repos.Risk}
	return repos
}

type failingWebhookFixtureRecords struct{ app.RiskRepository }

func (f failingWebhookFixtureRecords) InsertIncidentWebhookEvent(ctx context.Context, v domain.IncidentWebhookEvent, e domain.IncidentTimelineEvent) error {
	if err := f.RiskRepository.InsertIncidentWebhookEvent(ctx, v, e); err != nil {
		return err
	}
	return errors.New("private webhook failure after insert")
}

func TestOperationsFixtureSignedWebhookRollbackRecoveryAndBusinessReplay(t *testing.T) {
	now := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	memory := app.NewMemoryUnitOfWorkFactory()
	factory := &failingWebhookFixtureFactory{inner: memory}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { return now }})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", 32)))
	receiver, err := ledger.CreateIncidentWebhookReceiver(t.Context(), owner.actor, app.CreateIncidentWebhookReceiverInput{IncidentID: owner.incident.ID, Name: "Pager", Provider: "fixture", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"event_type":"contained","summary":"Containment recorded"}`)
	factory.fail = true
	callFixtureSignedWebhook(t, server, receiver.ID, private, now, "event", body, 500)
	after, err := memory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed callback committed partial effects", err)
	}
	factory.fail = false
	original := callFixtureSignedWebhook(t, server, receiver.ID, private, now, "event", body, 201)
	committed, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(committed.IncidentWebhookEvents) != len(before.IncidentWebhookEvents)+1 || len(committed.IncidentTimelineEvents) != len(before.IncidentTimelineEvents)+1 || len(committed.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(before.Idempotency, committed.Idempotency) {
		t.Fatal("callback used HTTP idempotency or lost atomic business effects")
	}
	assertTrustHTTPReplay(t, original, callFixtureSignedWebhook(t, server, receiver.ID, private, now, "event", body, 201))
	callFixtureSignedWebhook(t, server, receiver.ID, private, now, "event", append(append([]byte(nil), body...), ' '), 409)
	wrong := ed25519.NewKeyFromSeed([]byte(strings.Repeat("z", 32)))
	callFixtureSignedWebhook(t, server, receiver.ID, wrong, now, "bad-signature", body, 401)
	callFixtureSignedWebhook(t, server, receiver.ID, private, now.Add(-6*time.Minute), "expired", body, 401)
	after, err = memory.Snapshot()
	if err != nil || !reflect.DeepEqual(committed, after) {
		t.Fatal("replayed or rejected callback changed state", err)
	}
}
