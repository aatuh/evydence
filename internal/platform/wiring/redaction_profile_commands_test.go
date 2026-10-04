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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func redactionCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM redaction_profiles WHERE id<>'unrelated'),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func seedRedactionTenant(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other')ON CONFLICT(id)DO NOTHING;
UPDATE tenants SET name=repeat('private unrelated tenant metadata',300000)WHERE id='other';
INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('unrelated','other',repeat('private unrelated profile',300000),ARRAY['sbom'],ARRAY['token'],'redaction-profile.v1.0.0',now());`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresRedactionWritesOnlyProfileAndAudit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedRedactionTenant(t, p)
	c, err := BuildRedactionProfileCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRedactionProfileCommands(nil); err == nil {
		t.Fatal("missing transactions accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
	v, err := c.CreateRedactionProfile(t.Context(), a, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil || v.Name != "customer_safe" || redactionCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("focused profile failed", err)
	}
	var types, fields []string
	var actor, typ, hash string
	if err := p.QueryRow(t.Context(), `SELECT p.allowed_types,p.excluded_fields,a.actor_id,a.entry_type,coalesce(a.payload_hash,'')FROM redaction_profiles p JOIN audit_chain_entries a ON a.subject_id=p.id AND a.tenant_id=p.tenant_id WHERE p.id=$1`, v.ID).Scan(&types, &fields, &actor, &typ, &hash); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(types, v.AllowedTypes) || !reflect.DeepEqual(fields, v.ExcludedFields) || actor != "key" || typ != "redaction_profile.created" || hash != "" {
		t.Fatal("stored profile/audit differs")
	}
	a.TenantID = "missing"
	if _, err := c.CreateRedactionProfile(t.Context(), a, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"}); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("absent tenant created profile", err)
	}
	if err := c.AuthorizeCreateRedactionProfile(t.Context(), a, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"}); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatal("absent tenant replayed", err)
	}
	if redactionCounts(t, p) != [3]int{1, 1, 0} {
		t.Fatal("failed authority changed records")
	}
}

func TestPostgresRedactionFailuresAndDirectWriterValidation(t *testing.T) {
	for _, stage := range []string{"insert", "audit", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedRedactionTenant(t, p)
			c, err := BuildRedactionProfileCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			table := "redaction_profiles"
			if stage == "audit" {
				table = "audit_chain_entries"
			}
			trigger := `CREATE TRIGGER reject_redaction BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_redaction()`
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_redaction AFTER INSERT ON redaction_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_redaction()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_redaction()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private redaction SQL secret';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateRedactionProfile(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}, packageapp.CreateRedactionProfileInput{Preset: "customer_safe"})
			if err == nil || v.ID != "" || redactionCounts(t, p) != [3]int{} {
				t.Fatal("failed transaction committed profile", stage, err)
			}
		})
	}
	store, p := openHTMLReportWiringStore(t)
	seedRedactionTenant(t, p)
	for _, kind := range []string{"schema", "noncanonical", "duplicate", "nul", "foreign"} {
		v := packagedomain.RedactionProfile{ID: "bad", TenantID: "tenant", Name: "Customer", AllowedTypes: []string{"sbom"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: time.Now().UTC()}
		want := packageapp.ErrValidation
		switch kind {
		case "schema":
			v.SchemaVersion = "wrong"
		case "noncanonical":
			v.Name = " Customer "
		case "duplicate":
			v.AllowedTypes = []string{"sbom", "sbom"}
		case "nul":
			v.Description = "note\x00"
		case "foreign":
			v.TenantID = "absent"
			want = packageapp.ErrNotFound
		}
		err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
			w, ok := repos.Packages.(interface {
				InsertFocusedRedactionProfile(context.Context, packagedomain.RedactionProfile) error
			})
			if !ok {
				t.Fatal("focused profile writer absent")
			}
			return w.InsertFocusedRedactionProfile(ctx, v)
		})
		if !errors.Is(err, want) || redactionCounts(t, p) != [3]int{} {
			t.Fatal("forged durable profile accepted", kind, err)
		}
	}
}

func redactionHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.RedactionProfileCommands == nil {
		t.Fatal("redaction route still Ledger-backed", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/redaction-profiles", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private unrelated") || strings.Contains(w.Body.String(), "private redaction SQL secret") {
		t.Fatalf("unsafe/legacy redaction status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	return w.Body.String()
}

func TestPostgresRedactionHTTPRestartReplayAuthorityAndRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedRedactionTenant(t, p)
	const body = `{"preset":"customer_safe"}`
	one, two := redactionHTTP(t, store, "profile", body, 201), redactionHTTP(t, store, "profile", body, 201)
	var x, y any
	if json.Unmarshal([]byte(one), &x) != nil || json.Unmarshal([]byte(two), &y) != nil || !reflect.DeepEqual(x, y) || redactionCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("restart replay duplicated profile/audit")
	}
	redactionHTTP(t, store, "profile", `{"preset":"security_review"}`, 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='p'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	redactionHTTP(t, store, "profile", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';CREATE FUNCTION reject_redaction_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private redaction SQL secret';END$$;CREATE CONSTRAINT TRIGGER reject_redaction_http AFTER INSERT ON redaction_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_redaction_http()`); err != nil {
		t.Fatal(err)
	}
	redactionHTTP(t, store, "failed", body, 500)
	if redactionCounts(t, p) != [3]int{1, 1, 1} {
		t.Fatal("failed HTTP commit persisted replay/audit")
	}
	if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_redaction_http ON redaction_profiles`); err != nil {
		t.Fatal(err)
	}
	redactionHTTP(t, store, "failed", body, 201)
	if redactionCounts(t, p) != [3]int{2, 2, 2} {
		t.Fatal("failed key could not retry")
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	redactionHTTP(t, store, "profile", body, 401)
	if redactionCounts(t, p) != [3]int{2, 2, 2} {
		t.Fatal("revoked session mutated replay/profile")
	}
}

func TestPostgresRedactionFencePrecedesTenantLock(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "replay-guard"}[replay], func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedRedactionTenant(t, p)
			c, err := BuildRedactionProfileCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			leader, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
			if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
				in := packageapp.CreateRedactionProfileInput{Preset: "customer_safe"}
				if replay {
					done <- c.AuthorizeCreateRedactionProfile(ctx, a, in)
				} else {
					_, err := c.CreateRedactionProfile(ctx, a, in)
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("redaction bypassed writer fence", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("tenant locked before common writer fence", err)
					}
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("redaction did not resume", ctx.Err())
					}
					want := [3]int{1, 1, 0}
					if replay {
						want = [3]int{}
					}
					if redactionCounts(t, p) != want {
						t.Fatal("fenced replay/create effects differ")
					}
					return
				}
			}
		})
	}
}
