package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestPostgresIncidentCommandsUseFocusedAtomicWritesAndRestartReplay(t *testing.T) {
	if _, err := BuildIncidentCommands(nil); err == nil {
		t.Fatal("missing factory accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"incident:write"}}}}
	auth := &attestationHTTPActor{actor: a}
	counts := func() [6]int {
		t.Helper()
		var n [6]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM incidents),(SELECT count(*)FROM incident_timeline_events),(SELECT count(*)FROM remediation_tasks),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE state='pending' OR (state='failed' AND (response<>'null'::jsonb OR status<>0 OR owner_token_hash<>'' OR failed_at IS NULL))`).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("unsafe terminal key", unsafe, err)
		}
		return n
	}
	request := func(path, key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.IncidentCommands == nil {
			t.Fatal("incidents remain Ledger-backed", err)
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
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private") {
			t.Fatal(path, w.Code, w.Body.String(), noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("error contract")
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
	base := counts()
	incidentBody := `{"product_id":"product","release_id":"release","title":" Incident ","severity":" HIGH "}`
	incident := request("/v1/incidents", "incident", incidentBody, 201)
	if incident["tenant_id"] != "tenant" || incident["product_id"] != "product" || incident["release_id"] != "release" || incident["title"] != "Incident" || incident["severity"] != "high" || incident["status"] != "open" || incident["opened_at"] != incident["created_at"] {
		t.Fatal(incident)
	}
	id := incident["id"].(string)
	timelinePath := "/v1/incidents/" + id + "/timeline"
	timelineBody := `{"event_type":" contained ","summary":" Containment noted ","evidence_id":"ev-sbom"}`
	event := request(timelinePath, "timeline", timelineBody, 201)
	if event["incident_id"] != id || event["event_type"] != "contained" || event["summary"] != "Containment noted" || event["evidence_id"] != "ev-sbom" || event["occurred_at"] != event["created_at"] {
		t.Fatal(event)
	}
	taskBody := `{"incident_id":"` + id + `","release_id":"release","title":" Fix ","owner":" Team ","evidence_id":"ev-sbom","due_at":"2026-10-03T10:20:30.123456789+02:00"}`
	task := request("/v1/remediation-tasks", "task", taskBody, 201)
	if task["incident_id"] != id || task["release_id"] != "release" || task["owner"] != "Team" || task["title"] != "Fix" || task["status"] != "open" || task["evidence_id"] != "ev-sbom" || task["due_at"] != "2026-10-03T08:20:30.123456Z" {
		t.Fatal(task)
	}
	want := [6]int{base[0] + 1, base[1] + 1, base[2] + 1, base[3] + 3, base[4] + 3, base[5]}
	if counts() != want {
		t.Fatal("partial accepted writes", base, counts())
	}
	var attributed int
	if err := pool.QueryRow(ctx, `SELECT count(*)FROM audit_chain_entries WHERE actor_type='human_user' AND actor_id='human' AND entry_type IN ('incident.created','incident.timeline_recorded','remediation_task.created')`).Scan(&attributed); err != nil || attributed != 3 {
		t.Fatal(attributed, err)
	}
	for _, tc := range []struct {
		path, key, body string
		result          map[string]any
	}{{"/v1/incidents", "incident", incidentBody, incident}, {timelinePath, "timeline", timelineBody, event}, {"/v1/remediation-tasks", "task", taskBody, task}} {
		created, err := time.Parse(time.RFC3339Nano, tc.result["created_at"].(string))
		if err != nil || created.Nanosecond()%1000 != 0 {
			t.Fatal("timestamp precision", tc.result)
		}
		if replay := request(tc.path, tc.key, tc.body, 201); !reflect.DeepEqual(replay, tc.result) || counts() != want {
			t.Fatal("fresh instance replay changed record", replay, tc.result)
		}
		changed := strings.Replace(tc.body, " Incident ", "Changed", 1)
		if tc.path == timelinePath {
			changed = strings.Replace(tc.body, " Containment noted ", "Changed", 1)
		}
		if tc.path == "/v1/remediation-tasks" {
			changed = strings.Replace(tc.body, " Fix ", "Changed", 1)
		}
		request(tc.path, tc.key, changed, 409)
		auth.actor.ResourceGrants = nil
		request(tc.path, tc.key, tc.body, 403)
		auth.actor = a
		auth.actor.Scopes = []string{"evidence:write"}
		request(tc.path, "scope", tc.body, 403)
		auth.actor = a
		auth.actor.TenantID = "other"
		request(tc.path, "foreign", tc.body, 404)
		auth.actor = a
	}
	for i, bad := range []string{`{"event_type":"noted","summary":" "}`, `{"event_type":"noted","summary":"bad\u0000"}`, `{"event_type":"noted","summary":"Noted","evidence_id":null}`, `{"event_type":"noted","summary":"Noted","evidence_id":"missing"}`} {
		status := 400
		if i == 3 {
			status = 404
		}
		request(timelinePath, "invalid-timeline", bad, status)
	}
	request("/v1/incidents/missing/timeline", "missing-incident", timelineBody, 404)
	request("/v1/remediation-tasks", "missing-release", strings.Replace(taskBody, `"release"`, `"missing"`, 1), 404)
	request("/v1/remediation-tasks", "null-due", strings.Replace(taskBody, `"2026-10-03T10:20:30.123456789+02:00"`, `null`, 1), 400)
	if counts() != want {
		t.Fatal("guard rejection changed durable state", want, counts())
	}
	// Every reference must be current and granted, including an independently
	// authorized remediation release from a different product.
	if _, err := pool.Exec(ctx, `INSERT INTO products(id,tenant_id,name,slug)VALUES('second','tenant','Second','second');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('second-release','tenant','second','2','draft')`); err != nil {
		t.Fatal(err)
	}
	separate := strings.Replace(taskBody, `"release_id":"release"`, `"release_id":"second-release"`, 1)
	request("/v1/remediation-tasks", "separate", separate, 403)
	auth.actor.ResourceGrants = append(auth.actor.ResourceGrants, identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "second-release", Scopes: []string{"incident:write"}})
	request("/v1/remediation-tasks", "separate", separate, 201)
	auth.actor = a
	want[2]++
	want[3]++
	want[4]++
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET product_id='second',release_id='second-release',project_id=NULL,build_id=NULL,deployment_id=NULL WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	request(timelinePath, "timeline", timelineBody, 403)
	request("/v1/remediation-tasks", "task", taskBody, 403)
	if counts() != want {
		t.Fatal("stale evidence grant replay wrote")
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET product_id='product',release_id='release' WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	// Compound commands must see pending parents and roll back as one unit.
	commands, err := BuildIncidentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = executor.WithBody(ctx, a, "POST", "/compound-incident", "compound", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := commands.CreateIncident(ctx, a, operationsapp.CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Compound", Severity: "high"})
		if err != nil {
			return 0, nil, err
		}
		if _, err := commands.RecordIncidentTimelineEvent(ctx, a, v.ID, operationsapp.RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "ev-sbom"}); err != nil {
			return 0, nil, err
		}
		if _, err := commands.CreateRemediationTask(ctx, a, operationsapp.CreateRemediationTaskInput{IncidentID: v.ID, Title: "Fix", Owner: "Team"}); err != nil {
			return 0, nil, err
		}
		return 0, nil, app.ErrValidation
	})
	want[5]++
	if !errors.Is(err, app.ErrValidation) || counts() != want {
		t.Fatal("compound rollback leaked", err, counts())
	}
	// Inject failures after record insertion, at replay completion, and commit.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_incident_unit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private incident SQL';END$$`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"incidents", "incident_timeline_events", "remediation_tasks", "audit_chain_entries", "idempotency_records", "commit"} {
		table := stage
		path, body := "/v1/incidents", incidentBody
		if table == "incident_timeline_events" {
			path, body = timelinePath, timelineBody
		}
		if table == "remediation_tasks" {
			path, body = "/v1/remediation-tasks", taskBody
		}
		trigger := `CREATE TRIGGER reject_incident_test BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_incident_unit()`
		if table == "idempotency_records" {
			trigger = `CREATE TRIGGER reject_incident_test BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN (NEW.state='completed') EXECUTE FUNCTION reject_incident_unit()`
		}
		if table == "commit" {
			trigger = `CREATE CONSTRAINT TRIGGER reject_incident_test AFTER INSERT ON incidents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_incident_unit()`
			table = "incidents"
		}
		if _, err := pool.Exec(ctx, trigger); err != nil {
			t.Fatal(err)
		}
		request(path, "failure-"+stage, body, 500)
		// Command failures retain a response-free failed key. Completion and
		// commit failures instead roll the reservation itself back, allowing retry.
		if stage != "idempotency_records" && stage != "commit" {
			want[5]++
		}
		if counts() != want {
			t.Fatal("failed atomic command leaked", table, want, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_incident_test ON `+table); err != nil {
			t.Fatal(err)
		}
		if stage == "idempotency_records" || stage == "commit" {
			request(path, "failure-"+stage, body, 201)
			want[0]++
			want[3]++
			want[4]++
		} else {
			request(path, "failure-"+stage, body, 409)
		}
		if counts() != want {
			t.Fatal("failure retry changed effects", stage, want, counts())
		}
	}
}

func TestPostgresIncidentCommandsLockCurrentOwnershipAndAvoidDocumentReads(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildIncidentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"incident:write"}}}}
	incident, err := commands.CreateIncident(ctx, a, operationsapp.CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE incidents SET title=repeat('x',9000000) WHERE id=$1`, incident.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET metadata=jsonb_build_object('private',repeat('x',9000000));UPDATE releases SET version=repeat('x',65537);UPDATE products SET name=repeat('x',9000000) WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = executor.WithBody(ctx, a, "POST", "/incident-locks", "locks", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		if err := commands.AuthorizeRecordIncidentTimelineEvent(ctx, a, incident.ID, operationsapp.RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "ev-sbom"}); err != nil {
			return 0, nil, err
		}
		reader, ok := repos.Risk.(operationsapp.IncidentReader)
		if !ok {
			t.Fatal("missing reader")
		}
		for _, sql := range []string{`UPDATE incidents SET title=title WHERE id='` + incident.ID + `'`, `UPDATE evidence_items SET product_id=product_id WHERE id='ev-sbom'`, `UPDATE releases SET product_id=product_id WHERE id='release'`, `UPDATE products SET tenant_id=tenant_id WHERE id='product'`} {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, sql)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "55P03" {
				_ = tx.Rollback(ctx)
				t.Fatal("current owner row was not locked", sql, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for _, ref := range []struct{ tenant, kind, id string }{{"other", "incident", incident.ID}, {"other", "evidence", "ev-sbom"}, {"tenant", "incident", "missing"}, {"tenant", "evidence", "missing"}, {"tenant", "release", "missing"}, {"tenant", "product", "missing"}} {
			if _, err := reader.ReadIncidentSubject(ctx, ref.tenant, ref.kind, ref.id); !errors.Is(err, app.ErrNotFound) {
				t.Fatal(ref, err)
			}
		}
		if _, err := reader.ReadIncidentSubject(ctx, "tenant", "unsupported", "id"); !errors.Is(err, app.ErrValidation) {
			t.Fatal(err)
		}
		return 0, nil, app.ErrValidation
	})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatal(err)
	}
	// A reparented release makes both stored incident ownership and evidence
	// incoherent. It must fail closed, even for a tenant-wide human grant.
	if _, err := pool.Exec(ctx, `INSERT INTO products(id,tenant_id,name,slug)VALUES('second','tenant','Second','second');UPDATE releases SET product_id='second' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"incident:write"}}}
	if err := commands.AuthorizeRecordIncidentTimelineEvent(ctx, a, incident.ID, operationsapp.RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted"}); !errors.Is(err, operationsapp.ErrNotFound) {
		t.Fatal("incoherent incident parent accepted", err)
	}
}
