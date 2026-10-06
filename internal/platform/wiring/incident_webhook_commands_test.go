package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestPostgresIncidentWebhooksUseFocusedSignedAtomicCommandsAndCurrentReplay(t *testing.T) {
	if _, err := BuildIncidentWebhookCommands(nil); err == nil {
		t.Fatal("missing factory accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"incident:write"}}}}
	auth := &attestationHTTPActor{actor: a}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	counts := func() [6]int {
		t.Helper()
		var n [6]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM incident_webhook_receivers),(SELECT count(*)FROM incident_webhook_events),(SELECT count(*)FROM incident_timeline_events),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	request := func(path, key, body string, want int, public bool, extra string) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.IncidentWebhookCommands == nil {
			t.Fatal("webhooks remain Ledger-backed", err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		if public {
			at := time.Now().UTC().Format(time.RFC3339)
			r.Header.Set("X-Evydence-Webhook-Event-ID", key)
			r.Header.Set("X-Evydence-Webhook-Timestamp", at)
			signature := ed25519.Sign(private, []byte(at+"\n"+key+"\n"+body))
			r.Header.Set("X-Evydence-Webhook-Signature", "ed25519="+base64.StdEncoding.EncodeToString(signature))
			if extra == "bad-signature" {
				r.Header.Set("X-Evydence-Webhook-Signature", base64.RawStdEncoding.EncodeToString(make([]byte, 64)))
			} else if extra != "" {
				r.Header.Add(extra, r.Header.Get(extra))
			}
		} else {
			r.Header.Set("Authorization", "Bearer isolated-auth")
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private") {
			t.Fatal(path, w.Code, w.Body.String(), noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe error envelope")
			}
			return nil
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	incident := request("/v1/incidents", "incident", `{"product_id":"product","release_id":"release","title":"Incident","severity":"high"}`, 201, false, "")
	path := "/v1/incidents/" + incident["id"].(string) + "/webhook-receivers"
	body := `{"name":" Pager ","provider":" pager ","public_key":"` + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) + `"}`
	receiver := request(path, "receiver", body, 201, false, "")
	if receiver["name"] != "Pager" || receiver["provider"] != "pager" || receiver["status"] != "active" || receiver["public_key"] != base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) {
		t.Fatal(receiver)
	}
	before := counts()
	if replay := request(path, "receiver", body, 201, false, ""); !reflect.DeepEqual(receiver, replay) || counts() != before {
		t.Fatal("receiver restart replay changed", replay)
	}
	request(path, "receiver", strings.Replace(body, "Pager", "Changed", 1), 409, false, "")
	auth.actor.ResourceGrants = nil
	request(path, "receiver", body, 403, false, "")
	auth.actor = a
	auth.actor.TenantID = "other"
	request(path, "foreign", body, 404, false, "")
	auth.actor = a
	for i, bad := range []string{"null", "[]", body + " {}", strings.Replace(body, `"name":" Pager "`, `"name":null`, 1), strings.Replace(body, `"name":" Pager "`, `"name":"one","name":"two"`, 1), strings.Replace(body, `"provider":" pager "`, `"provider":"bad\u0000"`, 1), strings.Replace(body, `"public_key":"`, `"unknown":true,"public_key":"`, 1)} {
		request(path, fmt.Sprint("bad-", i), bad, 400, false, "")
	}
	if counts() != before {
		t.Fatal("receiver guard failure wrote")
	}
	publicPath := "/v1/incident-webhooks/" + receiver["id"].(string)
	eventBody := `{"event_type":" contained ","summary":" Containment ","evidence_id":"ev-sbom"}`
	event := request(publicPath, "provider-event", eventBody, 201, true, "")
	before[1]++
	before[2]++
	before[3]++
	if counts() != before {
		t.Fatal("public callback used HTTP replay or partial writes", before, counts())
	}
	if replay := request(publicPath, "provider-event", eventBody, 201, true, ""); !reflect.DeepEqual(event, replay) || counts() != before {
		t.Fatal("event restart replay changed", replay, event)
	}
	request(publicPath, "provider-event", "{", 409, true, "")
	request(publicPath, "bad-signature", "{", 401, true, "bad-signature")
	for _, header := range []string{"X-Evydence-Webhook-Event-ID", "X-Evydence-Webhook-Timestamp", "X-Evydence-Webhook-Signature"} {
		request(publicPath, "duplicate", eventBody, 400, true, header)
	}
	for i, bad := range []string{eventBody + " {}", strings.Replace(eventBody, `"event_type":" contained "`, `"event_type":"a","event_type":"b"`, 1), strings.Replace(eventBody, `"evidence_id":"ev-sbom"`, `"evidence_id":null`, 1), strings.Replace(eventBody, `"summary":" Containment "`, `"summary":"bad\u0000"`, 1), strings.Repeat(" ", 65537) + eventBody} {
		request(publicPath, fmt.Sprint("bad-event-", i), bad, 400, true, "")
	}
	request("/v1/incident-webhooks/missing", "missing", eventBody, 404, true, "")
	if _, err := pool.Exec(ctx, `INSERT INTO products(id,tenant_id,name,slug)VALUES('second','tenant','Second','second');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('second-release','tenant','second','2','draft');UPDATE evidence_items SET product_id='second',release_id='second-release',project_id=NULL,build_id=NULL,deployment_id=NULL WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	request(publicPath, "provider-event", eventBody, 404, true, "")
	request(publicPath, "new-foreign-evidence", eventBody, 404, true, "")
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET product_id='product',release_id='release' WHERE id='ev-sbom';UPDATE incident_webhook_receivers SET status='revoked'`); err != nil {
		t.Fatal(err)
	}
	request(publicPath, "provider-event", eventBody, 404, true, "")
	if _, err := pool.Exec(ctx, `UPDATE incident_webhook_receivers SET status='active',public_key=$1`, base64.RawStdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	request(publicPath, "provider-event", eventBody, 401, true, "")
	if _, err := pool.Exec(ctx, `UPDATE incident_webhook_receivers SET public_key=$1`, receiver["public_key"]); err != nil {
		t.Fatal(err)
	}
	if counts() != before {
		t.Fatal("invalid callbacks or stale authority wrote", before, counts())
	}
	// Concurrent copies must converge on one receipt, with one event and audit.
	var wg sync.WaitGroup
	results := make(chan map[string]any, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- request(publicPath, "concurrent", eventBody, 201, true, "") }()
	}
	wg.Wait()
	close(results)
	var original map[string]any
	for result := range results {
		if original == nil {
			original = result
		} else if !reflect.DeepEqual(original, result) {
			t.Fatal("concurrent replay diverged", original, result)
		}
	}
	before[1]++
	before[2]++
	before[3]++
	if counts() != before {
		t.Fatal("concurrent duplicate writes", before, counts())
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_webhook_unit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private webhook SQL';END$$`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"incident_timeline_events", "incident_webhook_events", "audit_chain_entries", "commit"} {
		table := stage
		trigger := `CREATE TRIGGER reject_webhook_test BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_webhook_unit()`
		if stage == "commit" {
			table = "incident_webhook_events"
			trigger = `CREATE CONSTRAINT TRIGGER reject_webhook_test AFTER INSERT ON incident_webhook_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_webhook_unit()`
		}
		if _, err := pool.Exec(ctx, trigger); err != nil {
			t.Fatal(err)
		}
		request(publicPath, "failure-"+stage, eventBody, 500, true, "")
		if counts() != before {
			t.Fatal("failed public transaction leaked", stage, before, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_webhook_test ON `+table); err != nil {
			t.Fatal(err)
		}
		request(publicPath, "failure-"+stage, eventBody, 201, true, "")
		before[1]++
		before[2]++
		before[3]++
	}
	if counts() != before {
		t.Fatal(before, counts())
	}
	// Receiver writes use the same human create/replay transaction discipline.
	for _, stage := range []string{"incident_webhook_receivers", "audit_chain_entries", "idempotency_records", "commit"} {
		table := stage
		trigger := `CREATE TRIGGER reject_webhook_test BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_webhook_unit()`
		if stage == "idempotency_records" {
			trigger = `CREATE TRIGGER reject_webhook_test BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_webhook_unit()`
		}
		if stage == "commit" {
			table = "incident_webhook_receivers"
			trigger = `CREATE CONSTRAINT TRIGGER reject_webhook_test AFTER INSERT ON incident_webhook_receivers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_webhook_unit()`
		}
		if _, err := pool.Exec(ctx, trigger); err != nil {
			t.Fatal(err)
		}
		request(path, "receiver-failure-"+stage, body, 500, false, "")
		if stage != "idempotency_records" && stage != "commit" {
			before[5]++
		}
		if counts() != before {
			t.Fatal("receiver failure leaked", stage, before, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_webhook_test ON `+table); err != nil {
			t.Fatal(err)
		}
		status := 409
		if stage == "idempotency_records" || stage == "commit" {
			status = 201
			before[0]++
			before[3]++
			before[4]++
		}
		request(path, "receiver-failure-"+stage, body, status, false, "")
		if counts() != before {
			t.Fatal("receiver failure retry changed effects", stage, before, counts())
		}
	}
}

func TestPostgresIncidentWebhooksUsePendingParentsAndLockCurrentReceiver(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildIncidentWebhookCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	incidents, err := BuildIncidentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"incident:write"}}}}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = executor.WithBody(ctx, a, "POST", "/compound-webhook", "compound", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		incident, err := incidents.CreateIncident(ctx, a, operationsapp.CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Pending", Severity: "high"})
		if err != nil {
			return 0, nil, err
		}
		r, err := commands.CreateIncidentWebhookReceiver(ctx, a, operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: incident.ID, Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))})
		if err != nil {
			return 0, nil, err
		}
		body := []byte(`{"event_type":"noted","summary":"Pending","evidence_id":"ev-sbom"}`)
		at := time.Now().UTC()
		signature := ed25519.Sign(private, append([]byte(at.Format(time.RFC3339)+"\nevent\n"), body...))
		if _, _, err := commands.HandleIncidentWebhook(ctx, operationsapp.HandleIncidentWebhookInput{ReceiverID: r.ID, EventID: "event", Timestamp: at, Signature: base64.RawStdEncoding.EncodeToString(signature), Body: body}); err != nil {
			return 0, nil, err
		}
		// The pending receiver is visible in this transaction, not outside it.
		var visible int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM incident_webhook_receivers WHERE id=$1`, r.ID).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("pending receiver escaped transaction", visible, err)
		}
		return 0, nil, app.ErrValidation
	})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatal("compound context lost", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM incidents)+(SELECT count(*)FROM incident_webhook_receivers)+(SELECT count(*)FROM incident_webhook_events)+(SELECT count(*)FROM incident_timeline_events)+(SELECT count(*)FROM audit_chain_entries)`).Scan(&n); err != nil || n != 0 {
		t.Fatal("compound rollback leaked", n, err)
	}
	incident, err := incidents.CreateIncident(ctx, a, operationsapp.CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := commands.CreateIncidentWebhookReceiver(ctx, a, operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: incident.ID, Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE incident_webhook_receivers SET name=repeat('x',9000000);UPDATE incidents SET title=repeat('x',9000000);UPDATE evidence_items SET metadata=jsonb_build_object('private',repeat('x',9000000))`); err != nil {
		t.Fatal(err)
	}
	// Both acceptance and natural replay ignore large unrelated documents.
	large := []byte(`{"event_type":"noted","summary":"` + strings.Repeat("x", 100000) + `","evidence_id":"ev-sbom"}`)
	at := time.Now().UTC()
	signature := ed25519.Sign(private, append([]byte(at.Format(time.RFC3339)+"\nlarge\n"), large...))
	in := operationsapp.HandleIncidentWebhookInput{ReceiverID: r.ID, EventID: "large", Timestamp: at, Signature: base64.RawStdEncoding.EncodeToString(signature), Body: large}
	record, event, err := commands.HandleIncidentWebhook(ctx, in)
	if err != nil || len(event.Summary) != 100000 {
		t.Fatal("large document affected point writes", err)
	}
	if v, e, err := commands.HandleIncidentWebhook(ctx, in); err != nil || v != record || e != event {
		t.Fatal("large bounded replay changed", err)
	}
	_, _, err = executor.WithBody(ctx, a, "POST", "/webhook-locks", "locks", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		reader, ok := repos.Risk.(operationsapp.IncidentWebhookReader)
		if !ok {
			t.Fatal("missing point reader")
		}
		v, err := reader.ReadIncidentWebhookReceiver(ctx, "tenant", r.ID)
		if err != nil || v.ID != r.ID || len(v.Name) > 65536 {
			t.Fatal("receiver document read", v, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `UPDATE incident_webhook_receivers SET status='revoked' WHERE id=$1`, r.ID)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" {
			t.Fatal("receiver not locked through commit", err)
		}
		if _, err := reader.ReadIncidentWebhookReceiver(ctx, "other", r.ID); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign receiver read", err)
		}
		return 0, nil, app.ErrValidation
	})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatal(err)
	}
}
