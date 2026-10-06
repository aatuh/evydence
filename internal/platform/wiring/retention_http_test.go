package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Unused raw-object ports are nil: retention must ask only the verifier port.
type retentionHTTPObjects struct {
	app.PayloadObjectStore
	app.BoundedObjectReader
	verifier *retentionProviderFake
}

func (p retentionHTTPObjects) VerifyObjectRetention(ctx context.Context, r app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	return p.verifier.VerifyObjectRetention(ctx, r)
}

func retentionHTTP(t *testing.T, store *postgres.Store, provider *retentionProviderFake, path, key, body string, want int) string {
	t.Helper()
	runtime := &Runtime{Process: API, Profile: PostgreSQL, Postgres: store}
	if provider != nil {
		runtime.Objects = retentionHTTPObjects{verifier: provider}
	}
	opts, err := BuildAPIReadServices(runtime, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.RetentionCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native retention wiring missing", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy retention status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if (want == 200 || want == 201) && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("successful retention response lost replay key")
	}
	return w.Body.String()
}
func retentionHTTPCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var v [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM object_retention_policies WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
		t.Fatal(err)
	}
	return v
}
func retentionHTTPPolicy(t *testing.T, body string) domain.ObjectRetentionPolicy {
	t.Helper()
	var v struct {
		Data domain.ObjectRetentionPolicy `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v.Data
}
func assertRetentionHTTPReplay(t *testing.T, a, b string) {
	t.Helper()
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil || !reflect.DeepEqual(x, y) {
		t.Fatalf("retention replay changed original record\noriginal: %s\nreplay: %s", a, b)
	}
}

func assertRetentionOuterLocksHeld(t *testing.T, p *pgxpool.Pool, policyID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' AND $1<>'' FOR UPDATE NOWAIT`, `SELECT id FROM object_retention_policies WHERE tenant_id='tenant' AND id=$1 FOR UPDATE NOWAIT`} {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, sql, policyID)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			t.Fatal("native replay guard released locks before provider observation", err)
		}
	}
}

func TestPostgresRetentionHTTPNativeCreationVerificationAndRestartReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE tenants SET name=repeat('private-unrelated-tenant',300000)WHERE id='other'`)
	hold := true
	provider := &retentionProviderFake{result: app.ObjectRetentionResult{Provider: "s3", Bucket: "bucket", ObjectKey: "tenants/tenant/raw/sample", Mode: "compliance", RetentionDays: 90, Enforced: true, LegalHold: &hold, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Checks: []domain.VerifyCheck{{Name: "provider_lock", Result: "passed"}}}}
	const path = "/v1/object-retention-policies"
	const body = `{"name":"Lock","mode":"compliance","retention_days":30,"object_key":"tenants/tenant/raw/sample","require_legal_hold":true}`
	one := retentionHTTP(t, store, provider, path, "create", body, 201)
	policy := retentionHTTPPolicy(t, one)
	if policy.ID == "" || policy.TenantID != "tenant" || policy.ObjectPrefix != "tenants/tenant/" || policy.Status != "configured" || policy.MaxVerificationAgeHours != 24 || policy.SchemaVersion != "object-retention-policy.v2.0.0" || provider.calls != 0 || retentionHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
		t.Fatal("creation lost defaults or atomicity", one)
	}
	assertRetentionHTTPReplay(t, one, retentionHTTP(t, store, provider, path, "create", body, 201))
	provider.hook = func() { assertRetentionOuterLocksHeld(t, p, policy.ID) }
	verifyPath := path + "/" + policy.ID + "/verify"
	receipt := retentionHTTP(t, store, provider, verifyPath, "verify", `{}`, 200)
	verified := retentionHTTPPolicy(t, receipt)
	if verified.ID != policy.ID || verified.Status != "verified" || verified.VerificationHash == "" || verified.VerificationProvider != "s3" || verified.VerificationBucket != "bucket" || verified.VerificationExpiresAt == nil || !verified.VerificationExpiresAt.Equal(provider.result.ObservedAt.Add(24*time.Hour)) || provider.calls != 1 || provider.request.TenantID != "tenant" || !provider.request.RequireLegalHold || retentionHTTPCounts(t, p) != [4]int{1, 2, 2, 0} {
		t.Fatal("native receipt contract/atomicity lost", receipt)
	}
	var hash, auditHash, actor string
	if err := p.QueryRow(t.Context(), `SELECT o.verification_hash,a.payload_hash,a.actor_id FROM object_retention_policies o JOIN audit_chain_entries a ON a.tenant_id=o.tenant_id AND a.subject_id=o.id AND a.entry_type='object_retention_policy.verified'WHERE o.id=$1`, policy.ID).Scan(&hash, &auditHash, &actor); err != nil || hash != verified.VerificationHash || auditHash != hash || actor != "user" {
		t.Fatal("stored receipt/audit differs", err)
	}
	// Poison mutable receipt metadata: replay authorization must select only
	// identity, not rebuild a current receipt or transfer an oversized record.
	exec(`UPDATE object_retention_policies SET verification_checks='{}',verification_limitations=ARRAY[repeat('private-current-metadata',400000)]WHERE id=$1`, policy.ID)
	assertRetentionHTTPReplay(t, receipt, retentionHTTP(t, store, provider, verifyPath, "verify", `{}`, 200))
	retentionHTTP(t, store, provider, verifyPath, "verify", ` {}`, 409)
	for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='missing'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`} {
		exec(sql)
		retentionHTTP(t, store, provider, path, "create", body, 403)
		retentionHTTP(t, store, provider, verifyPath, "verify", `{}`, 403)
	}
	exec(`UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant'`)
	exec(`UPDATE object_retention_policies SET tenant_id='other'WHERE id=$1`, policy.ID)
	retentionHTTP(t, store, provider, verifyPath, "verify", `{}`, 404)
	exec(`UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	retentionHTTP(t, store, provider, path, "create", body, 401)
	retentionHTTP(t, store, provider, verifyPath, "verify", `{}`, 401)
	if provider.calls != 1 || retentionHTTPCounts(t, p) != [4]int{0, 2, 2, 0} {
		t.Fatal("replay/revocation/foreign identity generated effects")
	}
}

func TestPostgresRetentionHTTPAtomicFailuresDoNotPublishReceiptOrReplay(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for _, stage := range []string{"write", "audit", "replay", "commit"} {
			t.Run(fmt.Sprintf("verify-%t/%s", verify, stage), func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedProviderReceiptHTTP(t, p)
				provider := &retentionProviderFake{}
				path, body := "/v1/object-retention-policies", `{"name":"Lock","mode":"governance","retention_days":30}`
				base := [4]int{}
				var policyID string
				if verify {
					c, err := BuildRetentionCommands(store, store, nil)
					if err != nil {
						t.Fatal(err)
					}
					v, err := c.CreateObjectRetentionPolicy(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}, verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30})
					if err != nil {
						t.Fatal(err)
					}
					policyID = v.ID
					path += "/" + v.ID + "/verify"
					body = `{}`
					base = [4]int{1, 1, 0, 0}
				}
				table, event := "object_retention_policies", "INSERT"
				if verify {
					event = "UPDATE"
				}
				if stage == "audit" {
					table, event = "audit_chain_entries", "INSERT"
				}
				if stage == "replay" {
					table, event = "idempotency_records", "UPDATE"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_retention_http BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_retention_http()", event, table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_retention_http BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_retention_http()`
				}
				if stage == "commit" {
					trigger = fmt.Sprintf("CREATE CONSTRAINT TRIGGER reject_retention_http AFTER %s ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_retention_http()", event, table)
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_retention_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-retention SQL password=secret';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				retentionHTTP(t, store, provider, path, "failed", body, 500)
				want := base
				if stage == "write" || stage == "audit" {
					want[3] = 1
				}
				if got := retentionHTTPCounts(t, p); got != want {
					t.Fatal("failed retention transaction published effects", got, want)
				}
				var leaked int
				if err := p.QueryRow(t.Context(), `SELECT count(*)FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb`).Scan(&leaked); err != nil || leaked != 0 {
					t.Fatal("failure retained result", leaked, err)
				}
				if verify {
					var status, hash string
					if err := p.QueryRow(t.Context(), `SELECT status,coalesce(verification_hash,'')FROM object_retention_policies WHERE id=$1`, policyID).Scan(&status, &hash); err != nil || status != "configured" || hash != "" || provider.calls != 1 {
						t.Fatal("failed commit kept observation", status, hash, err)
					}
				}
				if _, err := p.Exec(t.Context(), fmt.Sprintf("DROP TRIGGER reject_retention_http ON %s", table)); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[3] > 0 {
					key = "retry-new-key"
				}
				status := 201
				if verify {
					status = 200
				}
				retentionHTTP(t, store, provider, path, key, body, status)
				want[0] = 1
				want[1]++
				want[2] = 1
				if retentionHTTPCounts(t, p) != want {
					t.Fatal("safe retry duplicated effects")
				}
			})
		}
	}
}

func TestPostgresRetentionHTTPWithoutProviderStaysLocalIntent(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	const path = "/v1/object-retention-policies"
	v := retentionHTTPPolicy(t, retentionHTTP(t, store, nil, path, "create", `{"name":"Lock","mode":"governance","retention_days":30}`, 201))
	out := retentionHTTPPolicy(t, retentionHTTP(t, store, nil, path+"/"+v.ID+"/verify", "verify", `{}`, 200))
	if out.Status != "not_verified" || out.VerificationProvider != "" || out.VerificationObservedAt != nil || out.VerificationExpiresAt != nil || len(out.VerificationLimitations) == 0 || retentionHTTPCounts(t, p) != [4]int{1, 2, 2, 0} {
		t.Fatal("local intent became provider enforcement proof")
	}
}
