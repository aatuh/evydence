package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

var trustHTTPRoutes = []struct{ path, table, body, kind string }{
	{"/v1/signing-providers", "signing_providers", `{"name":"KMS","type":"aws_kms","key_ref":"key","encrypted":true}`, "signing_provider.created"},
	{"/v1/dsse-trust-roots", "dsse_trust_roots", `{"name":"Builder","key_id":"builder-key","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_predicate_types":["https://slsa.dev/provenance/v1"],"expected_builder_ids":["builder"],"required_claims":["external_parameters","builder_id"]}`, "dsse_trust_root.created"},
}

func trustHTTPCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var v [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM signing_providers WHERE tenant_id='tenant')+(SELECT count(*)FROM dsse_trust_roots WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
		t.Fatal(err)
	}
	return v
}

func trustHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.TrustConfigurationCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native trust configuration composition missing", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy trust route status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func TestPostgresTrustConfigurationHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	for _, route := range trustHTTPRoutes {
		t.Run(route.table, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := p.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			// Huge unrelated metadata must never become the command's authority.
			exec(`UPDATE tenants SET name=repeat('private-unrelated-tenant',300000)WHERE id='other';INSERT INTO signing_providers(id,tenant_id,name,type,status,key_ref,encrypted,schema_version,created_at)VALUES('unrelated','other',repeat('private-unrelated-provider',300000),'aws_kms','active','private-unrelated-ref',true,'signing-provider.v1',now())`)
			one := trustHTTP(t, store, route.path, "create", route.body, 201)
			var envelope struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &envelope); err != nil {
				t.Fatal(err)
			}
			id, ok := envelope.Data["id"].(string)
			if !ok || id == "" || envelope.Data["tenant_id"] != "tenant" || envelope.Data["status"] != "active" || envelope.Data["schema_version"] == "" || trustHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
				t.Fatal("trust metadata/audit/replay not atomic", one)
			}
			if route.table == "signing_providers" {
				var name, typ, ref string
				var encrypted bool
				if err := p.QueryRow(t.Context(), `SELECT name,type,key_ref,encrypted FROM signing_providers WHERE tenant_id='tenant'AND id=$1`, id).Scan(&name, &typ, &ref, &encrypted); err != nil || name != "KMS" || typ != "aws_kms" || ref != "key" || !encrypted || envelope.Data["key_ref"] != ref || envelope.Data["encrypted"] != encrypted {
					t.Fatal("stored/public provider metadata differs", err)
				}
			} else {
				var key, algorithm, public string
				var predicates, builders, claims []byte
				if err := p.QueryRow(t.Context(), `SELECT key_id,algorithm,public_key,allowed_predicate_types,expected_builder_ids,required_claims FROM dsse_trust_roots WHERE tenant_id='tenant'AND id=$1`, id).Scan(&key, &algorithm, &public, &predicates, &builders, &claims); err != nil || key != "builder-key" || algorithm != "Ed25519" || public != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || envelope.Data["key_id"] != key || envelope.Data["algorithm"] != algorithm || envelope.Data["public_key"] != public {
					t.Fatal("stored/public trust key differs", err)
				}
				for field, data := range map[string][]byte{"allowed_predicate_types": predicates, "expected_builder_ids": builders, "required_claims": claims} {
					var value any
					if json.Unmarshal(data, &value) != nil || !reflect.DeepEqual(value, envelope.Data[field]) {
						t.Fatal("stored/public trust policy differs", field)
					}
				}
				if !reflect.DeepEqual(envelope.Data["required_claims"], []any{"builder_id", "external_parameters"}) {
					t.Fatal("trust policy order changed")
				}
			}
			var subject, actor, kind, replay string
			if err := p.QueryRow(t.Context(), `SELECT a.subject_id,a.actor_id,a.entry_type,i.response::text FROM audit_chain_entries a JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='create'WHERE a.tenant_id='tenant'`).Scan(&subject, &actor, &kind, &replay); err != nil {
				t.Fatal(err)
			}
			if subject != id || actor != "user" || kind != route.kind || strings.Contains(replay, "private-") {
				t.Fatal("audit/replay contract changed")
			}
			two := trustHTTP(t, store, route.path, "create", route.body, 201)
			var x, y any
			if json.Unmarshal([]byte(one), &x) != nil || json.Unmarshal([]byte(two), &y) != nil || !reflect.DeepEqual(x, y) {
				t.Fatal("restart replay changed trust result")
			}
			trustHTTP(t, store, route.path, "create", strings.Replace(route.body, `"name":"`, `"name":"Changed `, 1), 409)
			trustHTTP(t, store, route.path, "malformed", strings.TrimSuffix(route.body, "}")+`,"NAME":null}`, 400)
			for _, sql := range []string{
				`UPDATE role_bindings SET resource_type='product',resource_id='missing'WHERE id='grant'`,
				`UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`,
				`UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='release_manager'WHERE id='grant'`,
			} {
				exec(sql)
				trustHTTP(t, store, route.path, "create", route.body, 403)
				trustHTTP(t, store, route.path, "fresh-denied", route.body, 403)
			}
			exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
			trustHTTP(t, store, route.path, "create", route.body, 401)
			if trustHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
				t.Fatal("replay/conflict/denial generated side effects")
			}
		})
	}
}

func TestPostgresTrustConfigurationHTTPFailuresRollbackMetadataAuditAndReplay(t *testing.T) {
	for _, route := range trustHTTPRoutes {
		for _, stage := range []string{"insert", "audit", "replay", "commit"} {
			t.Run(route.table+"/"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedProviderReceiptHTTP(t, p)
				table := route.table
				if stage == "audit" {
					table = "audit_chain_entries"
				}
				if stage == "replay" {
					table = "idempotency_records"
				}
				trigger := `CREATE TRIGGER reject_trust BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_trust()`
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_trust BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_trust()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_trust AFTER INSERT ON ` + table + ` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_trust()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_trust()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-trust SQL password=secret';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				trustHTTP(t, store, route.path, "failed", route.body, 500)
				want := [4]int{0, 0, 0, 1}
				if stage == "commit" || stage == "replay" {
					want[3] = 0
				}
				if got := trustHTTPCounts(t, p); got != want {
					t.Fatal("failed trust transaction published effects", got, want)
				}
				var unsafe int
				if err := p.QueryRow(t.Context(), `SELECT count(*)FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb`).Scan(&unsafe); err != nil || unsafe != 0 {
					t.Fatal("failure stored result", unsafe, err)
				}
				if stage == "commit" || stage == "replay" {
					if _, err := p.Exec(t.Context(), fmt.Sprintf("DROP TRIGGER reject_trust ON %s", table)); err != nil {
						t.Fatal(err)
					}
					trustHTTP(t, store, route.path, "failed", route.body, 201)
					if trustHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
						t.Fatal("failed commit key could not safely retry")
					}
				}
			})
		}
	}
}
