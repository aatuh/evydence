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

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type signingOperationWiringSigner struct {
	calls int
	phase string
}

func (f *signingOperationWiringSigner) Sign(_ context.Context, r app.SigningRequest) (app.SigningResult, error) {
	f.calls++
	if f.phase == "unavailable" {
		return app.SigningResult{}, app.ErrRetryableSigning
	}
	v := app.SigningResult{Signature: "signature", Algorithm: "external-aws_kms", ProviderID: r.ProviderID, ProviderType: r.ProviderType, KeyRef: r.KeyRef, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID, ProviderRequestID: "provider-receipt", KeyID: "public-key", Checks: []domain.VerifyCheck{{Name: "fake_executor", Result: "passed", Detail: "password=receipt-canary"}}}
	if f.phase == "mismatch" {
		v.RequestID = "another"
	}
	return v, nil
}

func TestPostgresSigningOperationRetryableProviderFailureDoesNotPoisonReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	seedSigningOperationProvider(t, p)
	f := &signingOperationWiringSigner{phase: "unavailable"}
	c, err := BuildSigningOperationCommands(store, f)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	in := verificationapp.SigningOperationInput{ProviderID: "sign-provider", SubjectType: "release", SubjectID: "release", PayloadHash: "sha256:" + strings.Repeat("a", 64)}
	uow := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeCreateSigningOperation(ctx, a, in)
	}}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateSigningOperation(ctx, a, in)
		if err != nil {
			return 0, nil, err
		}
		raw, err := verificationapp.EncodeSigningOperation(v)
		return 201, json.RawMessage(raw), err
	}
	if status, response, err := uow.WithBody(t.Context(), a, "POST", "/v1/signing-operations", "retry", []byte(`{}`), run); !errors.Is(err, app.ErrRetryableSigning) || status != 0 || response != nil || signingOperationCounts(t, p) != [4]int{} {
		t.Fatal("transient provider failure published records", err)
	}
	var reservations int
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records`).Scan(&reservations); err != nil || reservations != 0 {
		t.Fatal("transient provider failure poisoned retry key", err)
	}
	f.phase = ""
	if status, _, err := uow.WithBody(t.Context(), a, "POST", "/v1/signing-operations", "retry", []byte(`{}`), run); err != nil || status != 201 || f.calls != 2 || signingOperationCounts(t, p) != [4]int{1, 1, 1, 1} {
		t.Fatal("retry did not commit once", err)
	}
	if status, _, err := uow.WithBody(t.Context(), a, "POST", "/v1/signing-operations", "retry", []byte(`{}`), run); err != nil || status != 201 || f.calls != 2 || signingOperationCounts(t, p) != [4]int{1, 1, 1, 1} {
		t.Fatal("completed retry signed again", err)
	}
}
func TestPostgresSigningOperationHoldsProviderAndSubjectLocksThroughCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	seedSigningOperationProvider(t, p)
	c, err := BuildSigningOperationCommands(store, &signingOperationWiringSigner{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/signing-operations", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateSigningOperation(ctx, a, verificationapp.SigningOperationInput{ProviderID: "sign-provider", SubjectType: "release", SubjectID: "release", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
		if err != nil {
			return 0, nil, err
		}
		for _, sql := range []string{`SELECT 1 FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT 1 FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT 1 FROM releases WHERE id='release' FOR UPDATE NOWAIT`, `SELECT 1 FROM signing_providers WHERE id='sign-provider' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, sql)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("signing provider or root lock missing")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
			_ = tx.Rollback(ctx)
			return 0, nil, err
		}
		lockErr := coordination.LockWorkerProjection(ctx, tx, "tenant")
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
			return 0, nil, errors.New("signing worker fence missing")
		}
		return 201, v, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func signingOperationCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var n [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM provider_signature_receipts),(SELECT count(*)FROM signing_operations),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
		t.Fatal(err)
	}
	return n
}
func seedSigningOperationProvider(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `INSERT INTO signing_providers(id,tenant_id,name,type,status,key_ref,encrypted,schema_version,created_at)VALUES('sign-provider','tenant','Provider','aws_kms','active','key',true,'signing-provider.v1',now()),('foreign-provider','other','Other','aws_kms','active','key',true,'signing-provider.v1',now())`); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresSigningOperationUsesOwnedRootsAndNoRawProviderMetadata(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	seedSigningOperationProvider(t, p)
	f := &signingOperationWiringSigner{}
	c, err := BuildSigningOperationCommands(store, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSigningOperationCommands(nil, f); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	in := verificationapp.SigningOperationInput{ProviderID: "sign-provider", SubjectType: "release", SubjectID: "release", PayloadHash: "sha256:" + strings.Repeat("a", 64)}
	for _, root := range [][2]string{{"tenant", "tenant"}, {"product", "product"}, {"release", "release"}, {"build", "build"}, {"evidence", "b"}, {"customer_package", "package"}} {
		in.SubjectType, in.SubjectID = root[0], root[1]
		v, err := c.CreateSigningOperation(t.Context(), a, in)
		if err != nil || v.Result != "passed" || v.CanonicalPayloadHash == "" || v.RequestID == "" || v.SignatureRef == "" || len(v.Checks) != 5 {
			t.Fatal("signing operation contract changed", v, err)
		}
		var metadata string
		if err := p.QueryRow(t.Context(), `SELECT checks::text FROM signing_operations WHERE id=$1`, v.ID).Scan(&metadata); err != nil || strings.Contains(metadata, "receipt-canary") {
			t.Fatal("provider diagnostic credential persisted", err)
		}
	}
	before := signingOperationCounts(t, p)
	calls := f.calls
	in.SubjectType, in.SubjectID = "release", "release"
	for _, root := range [][2]string{{"tenant", "other"}, {"product", "other-product"}, {"evidence", "foreign"}, {"release", "missing"}} {
		bad := in
		bad.SubjectType, bad.SubjectID = root[0], root[1]
		if v, err := c.CreateSigningOperation(t.Context(), a, bad); !errors.Is(err, verificationapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign subject signed", err)
		}
	}
	bad := in
	bad.ProviderID = "foreign-provider"
	if _, err := c.CreateSigningOperation(t.Context(), a, bad); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign provider signed", err)
	}
	human := a
	human.KeyID, human.UserID = "", "user"
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
	if _, err := c.CreateSigningOperation(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product grant used for tenant signing administration", err)
	}
	if f.calls != calls || signingOperationCounts(t, p) != before {
		t.Fatal("denied command invoked signer or wrote")
	}
	if _, err := p.Exec(t.Context(), `UPDATE signing_providers SET status='revoked' WHERE id='sign-provider'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateSigningOperation(t.Context(), a, in); !errors.Is(err, verificationapp.ErrVerificationFailed) || f.calls != calls {
		t.Fatal("inactive provider signed", err)
	}
}
func TestPostgresSigningOperationFailuresRollbackLedgerNotProviderCall(t *testing.T) {
	for _, phase := range []string{"provider", "mismatch", "receipt", "operation", "audit", "commit"} {
		t.Run(phase, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSummaryMetadata(t, p)
			seedSigningOperationProvider(t, p)
			f := &signingOperationWiringSigner{phase: phase}
			c, err := BuildSigningOperationCommands(store, f)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "provider" {
				if _, err := p.Exec(t.Context(), `UPDATE signing_providers SET key_ref=repeat('k',9437184) WHERE id='sign-provider'`); err != nil {
					t.Fatal(err)
				}
			} else if phase != "mismatch" {
				target := map[string]string{"receipt": "provider_signature_receipts", "operation": "signing_operations", "audit": "audit_chain_entries", "commit": "signing_operations"}[phase]
				sql := `CREATE FUNCTION reject_signing_record()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private signing write';END$$;`
				if phase == "commit" {
					sql += `CREATE CONSTRAINT TRIGGER reject_signing_record AFTER INSERT ON ` + target + ` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_signing_record()`
				} else {
					sql += `CREATE TRIGGER reject_signing_record BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_signing_record()`
				}
				if _, err := p.Exec(t.Context(), sql); err != nil {
					t.Fatal(err)
				}
			}
			before := signingOperationCounts(t, p)
			v, err := c.CreateSigningOperation(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}, verificationapp.SigningOperationInput{ProviderID: "sign-provider", SubjectType: "release", SubjectID: "release", PayloadHash: "sha256:" + strings.Repeat("b", 64)})
			if err == nil || v.ID != "" || signingOperationCounts(t, p) != before {
				t.Fatal("failed command left ledger effects", v, err)
			}
			wantCalls := 1
			if phase == "provider" {
				wantCalls = 0
			}
			if f.calls != wantCalls {
				t.Fatal("provider invocation boundary differs", f.calls, wantCalls)
			}
		})
	}
}
func TestPostgresSigningOperationHTTPRestartReplayCurrentGrantAndProvider(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedSummaryMetadata(t, p)
	seedSigningOperationProvider(t, p)
	f := &signingOperationWiringSigner{}
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, SigningExecutor: f}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SigningOperationCommands == nil {
			t.Fatal("production signing still uses Ledger", err)
		}
		noReload := newAggregateLoadCanary(t, t.Context(), store)
		s, err := newNativeHTTPFixture(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/signing-operations", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(t.Context()) {
			t.Fatal("signing response or Ledger refresh differs", want, w.Code, noReload.Intact(t.Context()), w.Body.String())
		}
		if strings.Contains(w.Body.String(), "receipt-canary") || strings.Contains(w.Body.String(), "private signing") {
			t.Fatal("signing response leaked diagnostics")
		}
		return w.Body.Bytes()
	}
	body := fmt.Sprintf(`{"provider_id":"sign-provider","subject_type":"release","subject_id":"release","payload_hash":"sha256:%s"}`, strings.Repeat("a", 64))
	first := request("signing", body, 201)
	before := signingOperationCounts(t, p)
	var original, replay any
	if err := json.Unmarshal(first, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request("signing", body, 201), &replay); err != nil || !reflect.DeepEqual(original, replay) || f.calls != 1 || signingOperationCounts(t, p) != before {
		t.Fatal("replay re-signed", err, f.calls)
	}
	request("signing", strings.Replace(body, `"subject_id":"release"`, `"subject_id":"second-release"`, 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("signing", body, 403)
	request("fresh-denied", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant';UPDATE signing_providers SET status='revoked' WHERE id='sign-provider'`); err != nil {
		t.Fatal(err)
	}
	request("signing", body, 422)
	if _, err := p.Exec(t.Context(), `UPDATE signing_providers SET status='active' WHERE id='sign-provider';CREATE FUNCTION reject_signing_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private signing commit';END$$;CREATE CONSTRAINT TRIGGER reject_signing_commit AFTER INSERT ON signing_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_signing_commit()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit-failure", body, 500)
	if strings.Contains(string(failed), `"result":"passed"`) || f.calls != 2 || signingOperationCounts(t, p) != before {
		t.Fatal("commit failure exposed success or partial records")
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM releases WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("signing", body, 404)
	if signingOperationCounts(t, p) != before || f.calls != 2 {
		t.Fatal("replay guards changed signing records")
	}
}
