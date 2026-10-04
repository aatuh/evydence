package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func seedSigningKeyHTTP(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	if _, err := p.Exec(t.Context(), `INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('old','tenant','old','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519'),('foreign','other','foreign','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func signingKeyHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.SigningKeyCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native key composition missing", err)
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
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 200 && want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy signing-key route status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 200 || want == 201 {
		if w.Header().Get("Idempotency-Key") != key {
			t.Fatal("missing replay key")
		}
		var response struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		for field := range response.Data {
			if strings.Contains(field, "private") || strings.Contains(field, "secret") {
				t.Fatal("key material exposed", field)
			}
		}
	}
	return w.Body.String()
}

func signingKeyHTTPCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var v [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM signing_keys WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
		t.Fatal(err)
	}
	return v
}

var signingKeyHTTPRoutes = []struct {
	path, body, kind string
	status, keys     int
}{
	{"/v1/signing-keys/rotate", `{"reason":"scheduled"}`, "signing_key.rotated", 201, 2},
	{"/v1/signing-keys/old/revoke", `{"reason":"incident","semantics":"compromised","historical_validity_policy":"invalidate_all"}`, "signing_key.compromised", 200, 1},
}

func TestPostgresSigningKeyHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	for _, route := range signingKeyHTTPRoutes {
		t.Run(route.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSigningKeyHTTP(t, p)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := p.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			// A bounded public lifecycle operation never loads private bytes or
			// unrelated tenant state, even on fresh execution.
			exec(`UPDATE signing_keys SET encrypted_private_key=decode(repeat('ab',9*1024*1024),'hex')WHERE id='old';UPDATE tenants SET name=repeat('private-unrelated-tenant',300000)WHERE id='other'`)
			signingKeyHTTP(t, store, "/v1/signing-keys/foreign/revoke", "foreign", `{"reason":"incident"}`, 404)
			one := signingKeyHTTP(t, store, route.path, "create", route.body, route.status)
			var response struct {
				Data struct {
					ID, Status, PublicKey string
					TenantID              string `json:"tenant_id"`
					Version               int
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &response); err != nil {
				t.Fatal(err)
			}
			if response.Data.ID == "" || response.Data.TenantID != "tenant" || signingKeyHTTPCounts(t, p) != [4]int{route.keys, 1, 1, 0} {
				t.Fatal("key/audit/replay effects differ", one)
			}
			var actor, kind, subject, saved string
			if err := p.QueryRow(t.Context(), `SELECT a.actor_id,a.entry_type,a.subject_id,i.response::text FROM audit_chain_entries a JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='create'WHERE a.tenant_id='tenant'`).Scan(&actor, &kind, &subject, &saved); err != nil {
				t.Fatal(err)
			}
			if actor != "user" || kind != route.kind || subject != response.Data.ID || strings.Contains(saved, "private-") || strings.Contains(saved, "encrypted_private_key") {
				t.Fatal("unsafe key audit/replay")
			}
			if route.status == 201 {
				var oldStatus string
				var material []byte
				var public string
				if err := p.QueryRow(t.Context(), `SELECT encrypted_private_key,public_key,(SELECT status FROM signing_keys WHERE id='old')FROM signing_keys WHERE id=$1`, response.Data.ID).Scan(&material, &public, &oldStatus); err != nil {
					t.Fatal(err)
				}
				decoded, err := base64.RawStdEncoding.DecodeString(public)
				if err != nil || len(material) != ed25519.PrivateKeySize || !ed25519.PublicKey(material[32:]).Equal(ed25519.PublicKey(decoded)) || response.Data.Version != 2 || oldStatus != "retiring" {
					t.Fatal("native rotation format/lifecycle changed", err)
				}
				clear(material)
			} else {
				var policy, semantics string
				var compromised *time.Time
				if err := p.QueryRow(t.Context(), `SELECT historical_validity_policy,revocation_semantics,compromised_at FROM signing_keys WHERE id='old'`).Scan(&policy, &semantics, &compromised); err != nil || policy != "invalidate_all" || semantics != "compromised" || compromised == nil || response.Data.Status != "revoked" {
					t.Fatal("revocation semantics changed", err)
				}
			}
			// Current ownership is checked before replay, but the historical
			// result does not depend on today's key metadata or a fresh rotation.
			exec(`UPDATE signing_keys SET version=2147483647,revocation_reason=repeat('x',4097),encrypted_private_key=decode('ab','hex')WHERE id='old'`)
			assertRetentionHTTPReplay(t, one, signingKeyHTTP(t, store, route.path, "create", route.body, route.status))
			signingKeyHTTP(t, store, route.path, "create", strings.Replace(route.body, `"reason":"`, `"reason":"Changed `, 1), 409)
			for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='missing'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer'WHERE id='grant'`} {
				exec(sql)
				signingKeyHTTP(t, store, route.path, "create", route.body, 403)
				signingKeyHTTP(t, store, route.path, "fresh-denied", route.body, 403)
			}
			exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
			signingKeyHTTP(t, store, route.path, "create", route.body, 401)
			if signingKeyHTTPCounts(t, p) != [4]int{route.keys, 1, 1, 0} {
				t.Fatal("denied replay created effects")
			}
		})
	}
}

func TestPostgresSigningKeyHTTPFailuresRollbackLifecycleAuditAndReplay(t *testing.T) {
	for _, route := range signingKeyHTTPRoutes {
		for _, stage := range []string{"update", "insert", "audit", "replay", "commit"} {
			if route.status == 200 && stage == "insert" {
				continue
			}
			t.Run(route.kind+"/"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedSigningKeyHTTP(t, p)
				table, event := "signing_keys", "UPDATE"
				if stage == "insert" {
					event = "INSERT"
				}
				if stage == "audit" || stage == "commit" {
					table, event = "audit_chain_entries", "INSERT"
				}
				if stage == "replay" {
					table = "idempotency_records"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_key BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_key()", event, table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_key BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_key()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_key AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_key()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_key()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-key SQL password=secret';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				signingKeyHTTP(t, store, route.path, "failed", route.body, 500)
				want := [4]int{1, 0, 0, 1}
				if stage == "replay" || stage == "commit" {
					want[3] = 0
				}
				if signingKeyHTTPCounts(t, p) != want {
					t.Fatal("failed transaction published key/replay/audit", signingKeyHTTPCounts(t, p))
				}
				var status string
				var until, revoked *time.Time
				var reason string
				var unsafe int
				if err := p.QueryRow(t.Context(), `SELECT status,valid_until,revoked_at,revocation_reason,(SELECT count(*)FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb)FROM signing_keys WHERE id='old'`).Scan(&status, &until, &revoked, &reason, &unsafe); err != nil || status != "active" || until != nil || revoked != nil || reason != "" || unsafe != 0 {
					t.Fatal("rollback mutated existing key or saved result", err)
				}
				if stage == "replay" || stage == "commit" {
					if _, err := p.Exec(t.Context(), fmt.Sprintf("DROP TRIGGER reject_key ON %s", table)); err != nil {
						t.Fatal(err)
					}
					signingKeyHTTP(t, store, route.path, "failed", route.body, route.status)
					if signingKeyHTTPCounts(t, p) != [4]int{route.keys, 1, 1, 0} {
						t.Fatal("failed commit could not retry")
					}
				}
			})
		}
	}
}
