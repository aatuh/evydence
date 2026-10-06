package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

type nativeDeploymentCase struct{ kind, path, body string }

func nativeDeploymentCases() []nativeDeploymentCase {
	return []nativeDeploymentCase{
		{"environment", "/v1/environments", `{"product_id":" product ","name":" Production ","kind":" production "}`},
		{"event", "/v1/deployments", `{"environment_id":" env ","release_id":" release ","artifact_ids":["artifact-b","artifact","artifact-b"],"status":" rolled_back ","rollback_of":" rollback ","started_at":"2026-10-01T12:00:00.123456789+03:00","finished_at":"2026-10-01T08:00:00.987654321Z"}`},
	}
}

func (c nativeDeploymentCase) eventInput() operationsapp.RecordDeploymentInput {
	finished := time.Date(2026, 10, 1, 8, 0, 0, 987654321, time.UTC)
	return operationsapp.RecordDeploymentInput{EnvironmentID: "env", ReleaseID: "release", ArtifactIDs: []string{"artifact-b", "artifact", "artifact-b"}, Status: "rolled_back", RollbackOf: "rollback", StartedAt: time.Date(2026, 10, 1, 9, 0, 0, 123456789, time.UTC), FinishedAt: &finished}
}
func (c nativeDeploymentCase) guard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) error {
	if c.kind == "environment" {
		return o.DeploymentEnvironmentCommands.AuthorizeEnvironmentCreation(ctx, a, operationsapp.CreateEnvironmentInput{ProductID: "product", Name: "Production", Kind: "production"})
	}
	return o.DeploymentCommands.AuthorizeDeploymentRecording(ctx, a, c.eventInput())
}
func (c nativeDeploymentCase) create(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) (int, any, error) {
	if c.kind == "environment" {
		v, err := o.DeploymentEnvironmentCommands.CreateDeploymentEnvironment(ctx, a, operationsapp.CreateEnvironmentInput{ProductID: "product", Name: "Production", Kind: "production"})
		return 201, domain.DeploymentEnvironment(v), err
	}
	v, err := o.DeploymentCommands.RecordDeployment(ctx, a, c.eventInput())
	return 201, domain.DeploymentEvent(v), err
}
func (c nativeDeploymentCase) addEffects(n [7]int) [7]int {
	if c.kind == "environment" {
		n[0]++
		n[3]++
	} else {
		n[1]++
		n[2]++
		n[3] += 2
	}
	n[5]++
	return n
}

func seedDeploymentCreationNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO releases(id,tenant_id,product_id,version,state,created_at)VALUES('release','tenant','product','1','draft',now()),('other-release','tenant','other-product','2','draft',now()),('foreign-release','other','foreign-product','1','draft',now());
INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at)VALUES('env','tenant','product','Existing','production','deployment-environment.v1.0.0',now()),('other-env','tenant','product','Canary','production','deployment-environment.v1.0.0',now()),('foreign-env','other','foreign-product','Foreign','production','deployment-environment.v1.0.0',now());
INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest,created_at)VALUES('artifact','tenant','A','application/octet-stream',1,'sha256:a',now()),('artifact-b','tenant','B','application/octet-stream',1,'sha256:b',now()),('foreign-artifact','other','Foreign','application/octet-stream',1,'sha256:c',now());
INSERT INTO deployment_events(id,tenant_id,environment_id,release_id,status,started_at,schema_version,created_at)VALUES('rollback','tenant','env','release','succeeded',now(),'deployment-event.v1.0.0',now()),('other-rollback','tenant','other-env','release','succeeded',now(),'deployment-event.v1.0.0',now()),('foreign-rollback','other','foreign-env','foreign-release','succeeded',now(),'deployment-event.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
}
func deploymentCreationNativeCounts(t *testing.T, p *pgxpool.Pool) [7]int {
	t.Helper()
	var n [7]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM deployment_environments),(SELECT count(*)FROM deployment_events),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
		t.Fatal(err)
	}
	return n
}

func deploymentCreationNativeHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native deployment path=%s status=%d want=%d loads=%d: %s", path, w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("deployment lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("deployment lost Problem Details")
	}
	return w.Body.String()
}

func assertDeploymentCreationReplay(t *testing.T, one, two string) {
	t.Helper()
	decode := func(s string) any {
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !reflect.DeepEqual(decode(one), decode(two)) {
		t.Fatalf("deployment public fields changed\noriginal: %s\nreplay: %s", one, two)
	}
}

func TestPostgresEnvironmentNativeNaturalReusePreservesEveryPublicField(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	body := `{"product_id":" product ","name":" Production ","kind":" production "}`
	one := deploymentCreationNativeHTTP(t, store, "/v1/environments", "original", body, 201)
	var e struct {
		Data domain.DeploymentEnvironment `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.Name != "Production" || e.Data.Kind != "production" || e.Data.TenantID != "tenant" || e.Data.ProductID != "product" || e.Data.CreatedAt.IsZero() {
		t.Fatal("environment contract changed", one, err)
	}
	assertDeploymentCreationReplay(t, one, deploymentCreationNativeHTTP(t, store, "/v1/environments", "original", body, 201))
	changed := strings.Replace(body, " production ", " canary ", 1)
	assertDeploymentCreationReplay(t, one, deploymentCreationNativeHTTP(t, store, "/v1/environments", "natural-reuse", changed, 201))
	var environments, audits int
	if err := p.QueryRow(t.Context(), `SELECT (SELECT count(*)FROM deployment_environments),(SELECT count(*)FROM audit_chain_entries)`).Scan(&environments, &audits); err != nil || environments != 1 || audits != 1 {
		t.Fatal("natural reuse duplicated or mutated environment", environments, audits, err)
	}
}

func TestPostgresDeploymentCreationNativeReplayAndCurrentAuthority(t *testing.T) {
	for _, c := range nativeDeploymentCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedDeploymentCreationNative(t, p)
			baseline := deploymentCreationNativeCounts(t, p)
			invalidReferences := []string{strings.Replace(c.body, `" product "`, `"foreign-product"`, 1), strings.Replace(c.body, `" product "`, `"missing"`, 1)}
			if c.kind == "event" {
				invalidReferences = []string{
					strings.Replace(c.body, `" env "`, `"foreign-env"`, 1),
					strings.Replace(c.body, `" release "`, `"foreign-release"`, 1),
					strings.Replace(c.body, `" release "`, `"other-release"`, 1),
					strings.ReplaceAll(c.body, `"artifact-b"`, `"foreign-artifact"`),
					strings.Replace(c.body, `" rollback "`, `"foreign-rollback"`, 1),
					strings.Replace(c.body, `" rollback "`, `"other-rollback"`, 1),
					strings.Replace(c.body, `" rollback "`, `"missing"`, 1),
				}
			}
			for n, invalid := range invalidReferences {
				deploymentCreationNativeHTTP(t, store, c.path, fmt.Sprintf("foreign-%d", n), invalid, 404)
			}
			if got := deploymentCreationNativeCounts(t, p); got != baseline {
				t.Fatal("foreign deployment references reserved replay or wrote effects", got, baseline)
			}
			one := deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 201)
			var e struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil || string(e.Data["tenant_id"]) != `"tenant"` || len(e.Data["id"]) < 3 {
				t.Fatal("deployment creation changed contract", one, err)
			}
			if c.kind == "event" {
				if string(e.Data["artifact_ids"]) != `["artifact","artifact-b","artifact-b"]` || string(e.Data["started_at"]) != `"2026-10-01T09:00:00.123456Z"` || string(e.Data["finished_at"]) != `"2026-10-01T08:00:00.987654Z"` || string(e.Data["rollback_of"]) != `"rollback"` {
					t.Fatal("deployment normalization, duplicate or timestamp semantics changed", one)
				}
				var evidenceID string
				if err := json.Unmarshal(e.Data["evidence_id"], &evidenceID); err != nil || evidenceID == "" {
					t.Fatal(one, err)
				}
				point, err := store.GetEvidencePoint(t.Context(), "tenant", evidenceID, func(_ application.ResourceReferences) error { return nil })
				if err != nil || point.Item.DeploymentID == "" || point.Item.ReleaseID != "release" {
					t.Fatal("deployment evidence not immediately readable", point, err)
				}
				if got, err := (evidenceCanonicalHasher{}).HashEvidence(t.Context(), point.Item); err != nil || got != point.Item.CanonicalHash {
					t.Fatal("deployment commitment changed on database round trip", got, err)
				}
			}
			assertDeploymentCreationReplay(t, one, deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 201))
			deploymentCreationNativeHTTP(t, store, c.path, "original", c.body+" ", 409)
			want := c.addEffects(baseline)
			if c.kind == "event" {
				minimal := `{"environment_id":"env","release_id":"release","status":"started"}`
				defaulted := deploymentCreationNativeHTTP(t, store, c.path, "default-start", minimal, 201)
				var d struct {
					Data domain.DeploymentEvent `json:"data"`
				}
				if err := json.Unmarshal([]byte(defaulted), &d); err != nil || d.Data.StartedAt.IsZero() || !d.Data.StartedAt.Equal(d.Data.CreatedAt) || d.Data.StartedAt.Nanosecond()%1000 != 0 || d.Data.FinishedAt != nil || len(d.Data.ArtifactIDs) != 0 {
					t.Fatal("deployment omitted-field defaults changed", defaulted, err)
				}
				assertDeploymentCreationReplay(t, defaulted, deploymentCreationNativeHTTP(t, store, c.path, "default-start", minimal, 201))
				want = c.addEffects(want)
			}
			if got := deploymentCreationNativeCounts(t, p); got != want {
				t.Fatal("deployment retry wrote effects", got, want)
			}
			o := subjectVerificationOptions(t, store, nil)
			a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "historical", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(context.Context) (int, any, error) {
				return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
			}); err != nil {
				t.Fatal(err)
			}
			want[5]++
			if _, err := p.Exec(t.Context(), `UPDATE products SET name=repeat('private-',1200000);UPDATE deployment_environments SET kind=repeat('private-',1200000);UPDATE releases SET state=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000);UPDATE deployment_events SET status=repeat('private-',1200000)WHERE id='rollback'`); err != nil {
				t.Fatal(err)
			}
			assertDeploymentCreationReplay(t, one, deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 201))
			if out := deploymentCreationNativeHTTP(t, store, c.path, "historical", c.body, 201); !strings.Contains(out, "9007199254740993") {
				t.Fatal("deployment replay rounded exact number", out)
			}
			for _, grant := range []struct {
				kind, id string
				allowed  bool
			}{{"product", "product", true}, {"release", "release", c.kind == "event"}, {"environment", "env", false}, {"project", "project", false}, {"product", "other-product", false}, {"tenant", "other", false}} {
				if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
					t.Fatal(err)
				}
				status := 403
				if grant.allowed {
					status = 201
				}
				deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, status)
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
				t.Fatal(err)
			}
			deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 404)
			if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product'`); err != nil {
				t.Fatal(err)
			}
			if c.kind == "event" {
				for _, m := range []struct{ change, restore string }{
					{`UPDATE deployment_environments SET tenant_id='other'WHERE id='env'`, `UPDATE deployment_environments SET tenant_id='tenant'WHERE id='env'`},
					{`UPDATE releases SET product_id='other-product'WHERE id='release'`, `UPDATE releases SET product_id='product'WHERE id='release'`},
					{`UPDATE artifacts SET tenant_id='other'WHERE id='artifact-b'`, `UPDATE artifacts SET tenant_id='tenant'WHERE id='artifact-b'`},
					{`UPDATE deployment_events SET environment_id='other-env'WHERE id='rollback'`, `UPDATE deployment_events SET environment_id='env'WHERE id='rollback'`},
				} {
					if _, err := p.Exec(t.Context(), m.change); err != nil {
						t.Fatal(err)
					}
					deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 404)
					if _, err := p.Exec(t.Context(), m.restore); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
				t.Fatal(err)
			}
			deploymentCreationNativeHTTP(t, store, c.path, "original", c.body, 401)
			if got := deploymentCreationNativeCounts(t, p); got != want {
				t.Fatal("deployment replay or denial mutated state", got, want)
			}
		})
	}
}

func TestPostgresDeploymentCreationNativeRollbackAndRecovery(t *testing.T) {
	for _, c := range nativeDeploymentCases() {
		stages := []string{"record", "audit", "replay", "commit"}
		if c.kind == "event" {
			stages = []string{"evidence", "evidence-audit", "audit", "record", "replay", "commit"}
		}
		for _, stage := range stages {
			t.Run(c.kind+"/"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedDeploymentCreationNative(t, p)
				baseline := deploymentCreationNativeCounts(t, p)
				table := "deployment_environments"
				if c.kind == "event" {
					table = "deployment_events"
				}
				if stage != "record" {
					table = map[string]string{"evidence": "evidence_items", "evidence-audit": "audit_chain_entries", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_native_deployment BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_deployment()", table)
				if stage == "audit" && c.kind == "event" {
					trigger = `CREATE TRIGGER reject_native_deployment BEFORE INSERT ON audit_chain_entries FOR EACH ROW WHEN(NEW.entry_type='deployment.recorded')EXECUTE FUNCTION reject_native_deployment()`
				}
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_native_deployment BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_deployment()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_native_deployment AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_deployment()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_deployment()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-deployment-write-failure';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				deploymentCreationNativeHTTP(t, store, c.path, "failed", c.body, 500)
				want := baseline
				businessFailure := stage != "replay" && stage != "commit"
				if businessFailure {
					want[6]++
				}
				if got := deploymentCreationNativeCounts(t, p); got != want {
					t.Fatal("deployment partially committed", stage, got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_deployment ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if businessFailure {
					deploymentCreationNativeHTTP(t, store, c.path, key, c.body, 409)
					key = "recovered"
				}
				one := deploymentCreationNativeHTTP(t, store, c.path, key, c.body, 201)
				assertDeploymentCreationReplay(t, one, deploymentCreationNativeHTTP(t, store, c.path, key, c.body, 201))
				want = c.addEffects(want)
				if got := deploymentCreationNativeCounts(t, p); got != want {
					t.Fatal("deployment recovery duplicated effects", stage, got, want)
				}
			})
		}
	}
}
