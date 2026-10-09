package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type customerAuditHasher struct{}

func (customerAuditHasher) Hash(v any) (string, error) { return application.NormalizedJSONHash(v) }

func customerAuditFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", ed25519.SeedSize)))
	for _, row := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('audit_key','tenant','key','Ed25519','active',$1,$2,'2026-10-01T00:00:00Z','2026-10-01T00:00:00Z',1,'local_ed25519')`, []any{base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), []byte("sealed-key-must-not-cross-driver")}},
		{`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at) VALUES('audit_signature','tenant','merkle_batch','audit_batch','audit_key','Ed25519',$1,'2026-10-03T00:00:00Z')`, []any{base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte("hash")))}},
		{`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at) VALUES('audit_batch','tenant',1,1,1,'{hash}','hash','{audit_signature}','merkle-batch.v1','2026-10-03T00:00:00Z')`, nil},
	} {
		if _, err := s.pool.Exec(t.Context(), row.sql, row.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.ExecuteUnitOfWork(t.Context(), s, func(ctx context.Context, repos app.Repositories) error {
		for n := 1; n <= 130; n++ {
			e := domain.AuditChainEntry{ID: fmt.Sprintf("audit_%03d", n), TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "private-subject-marker", ActorType: "api_key", ActorID: "private-actor-marker", OccurredAt: customerGovernanceNow.Add(-time.Hour), Metadata: map[string]any{"private": "private-audit-marker"}}
			if n == 130 {
				e.SubjectType, e.SubjectID, e.SignatureRef = "merkle_batch", "audit_batch", "audit_signature"
			}
			if _, err := repos.Audit.Append(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCustomerPackageAuditSnapshotVerifiesAndExportsOnlyAggregate(t *testing.T) {
	s := customerAuditFixture(t)
	tx := &customerAuditWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget, customerAuditHasher{}, localed25519.PayloadVerifier{})
	if err != nil || v["result"] != "passed" || v["latest_sequence"] != int64(130) || !reflect.DeepEqual(v["checks"], []map[string]any{{"name": "audit_chain_integrity", "result": "passed"}}) {
		t.Fatal("native integrity summary", v, err)
	}
	var head string
	if err := tx.QueryRow(t.Context(), `SELECT entry_hash FROM audit_chain_entries WHERE tenant_id='tenant' ORDER BY sequence DESC LIMIT 1`).Scan(&head); err != nil || v["head_hash"] != head {
		t.Fatal("summary used a synthetic head", v, err)
	}
	body, err := json.Marshal(v)
	if err != nil || tx.privateKeyFound || tx.pages < 3 || strings.Contains(string(body), "private-") || strings.Contains(string(body), "audit_signature") || strings.Contains(string(body), "audit_001") || packageapp.MaxCustomerPackageManifestBytes-budget.remainingBytes != len(body) {
		t.Fatalf("internal audit data exported: %s budget=%d err=%v", body, budget.remainingBytes, err)
	}
	exact := &customerSnapshotBudget{remainingBytes: len(body)}
	if same, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, exact, customerAuditHasher{}, localed25519.PayloadVerifier{}); err != nil || !reflect.DeepEqual(same, v) || exact.remainingBytes != 0 {
		t.Fatal("exact audit-summary budget", same, exact, err)
	}
	for _, remaining := range []int{0, len(body) - 1} {
		b := &customerSnapshotBudget{remainingBytes: remaining}
		if v, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, b, customerAuditHasher{}, localed25519.PayloadVerifier{}); !errors.Is(err, packageapp.ErrConflict) || v != nil || b.remainingBytes != remaining {
			t.Fatal("partial over-budget audit result", v, b, err)
		}
	}
	for _, scope := range [][3]string{{"tenant", "product", "sibling_release"}, {"foreign_tenant", "product", "release"}, {"tenant", "foreign_product", ""}} {
		if v, err := readCustomerPackageAuditTx(t.Context(), tx, scope[0], scope[1], scope[2], customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{}); !errors.Is(err, packageapp.ErrNotFound) || v != nil {
			t.Fatal("foreign package scope gained audit summary", v, err)
		}
	}
	other, err := readCustomerPackageAuditTx(t.Context(), tx, "foreign_tenant", "foreign_product", "foreign_release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{})
	if err != nil || other["result"] != "passed" || other["latest_sequence"] != int64(0) || other["head_hash"] != "" {
		t.Fatal("foreign tenant's empty chain borrowed own entries", other, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM verification_results)+(SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("read-only audit effects=%d err=%v", effects, err)
	}
}

type customerAuditWatchTx struct {
	pgx.Tx
	largest, pages  int
	privateKeyFound bool
}

func (w *customerAuditWatchTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := w.Tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	if strings.Contains(sql, "WITH selected AS MATERIALIZED") {
		w.pages++
	}
	w.privateKeyFound = w.privateKeyFound || strings.Contains(sql, "encrypted_private_key")
	return customerAuditWatchRows{Rows: rows, watch: w}, nil
}

type customerAuditWatchRows struct {
	pgx.Rows
	watch *customerAuditWatchTx
}

func (r customerAuditWatchRows) Scan(dest ...any) error {
	if err := r.Rows.Scan(dest...); err != nil {
		return err
	}
	for _, value := range dest {
		var raw string
		switch v := value.(type) {
		case *[]byte:
			raw = string(*v)
		case *string:
			raw = *v
		}
		if len(raw) > r.watch.largest {
			r.watch.largest = len(raw)
		}
		secret := "sealed-key-must-not-cross-driver"
		r.watch.privateKeyFound = r.watch.privateKeyFound || strings.Contains(raw, secret) || strings.Contains(raw, hex.EncodeToString([]byte(secret)))
	}
	return nil
}

func TestCustomerPackageAuditSnapshotRejectsSourceOverflowBeforeTransfer(t *testing.T) {
	s := customerAuditFixture(t)
	for _, tc := range []struct{ name, sql string }{
		{"single entry", `UPDATE audit_chain_entries SET metadata=jsonb_build_object('large',repeat('x',8388609)) WHERE id='audit_001'`},
		{"cumulative page", `UPDATE audit_chain_entries SET metadata=jsonb_build_object('large',repeat('x',4194304)) WHERE id IN ('audit_001','audit_002')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, `UPDATE audit_chain_entries SET metadata='{"private":"private-audit-marker"}' WHERE id IN ('audit_001','audit_002')`)
			tx := &customerAuditWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: 1024}
			v, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget, customerAuditHasher{}, localed25519.PayloadVerifier{})
			if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != 1024 || tx.largest != 0 || tx.privateKeyFound {
				t.Fatalf("overflow audit source transferred: value=%#v bytes=%d budget=%d err=%v", v, tx.largest, budget.remainingBytes, err)
			}
		})
	}
}

func TestCustomerPackageAuditSnapshotDetectsTamperingAndSigningLifecycle(t *testing.T) {
	s := customerAuditFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"canonical metadata", `UPDATE audit_chain_entries SET metadata='{"changed":true}' WHERE id='audit_001'`, `UPDATE audit_chain_entries SET metadata='{"private":"private-audit-marker"}' WHERE id='audit_001'`},
		{"predecessor", `UPDATE audit_chain_entries SET previous_entry_hash='sha256:wrong' WHERE id='audit_002'`, `UPDATE audit_chain_entries SET previous_entry_hash=(SELECT entry_hash FROM audit_chain_entries WHERE id='audit_001') WHERE id='audit_002'`},
		{"signature subject", `UPDATE signatures SET subject_id='other' WHERE id='audit_signature'`, `UPDATE signatures SET subject_id='audit_batch' WHERE id='audit_signature'`},
		{"signature tenant", `UPDATE signatures SET tenant_id='foreign_tenant' WHERE id='audit_signature'`, `UPDATE signatures SET tenant_id='tenant' WHERE id='audit_signature'`},
		{"key tenant", `UPDATE signing_keys SET tenant_id='foreign_tenant' WHERE id='audit_key'`, `UPDATE signing_keys SET tenant_id='tenant' WHERE id='audit_key'`},
		{"compromised key", `UPDATE signing_keys SET revocation_semantics='compromised',historical_validity_policy='invalidate_all' WHERE id='audit_key'`, `UPDATE signing_keys SET revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='audit_key'`},
		{"bound payload", `UPDATE merkle_batches SET root_hash='other' WHERE id='audit_batch'`, `UPDATE merkle_batches SET root_hash='hash' WHERE id='audit_batch'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			v, err := readCustomerPackageAuditTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{})
			if err != nil || v["result"] != "failed" {
				t.Fatal("tampered chain represented as passed", v, err)
			}
		})
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE signing_keys SET status='revoked',revoked_at='2026-10-04T11:00:00Z',revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='audit_key'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageAuditTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{})
	if err != nil || v["result"] != "passed" {
		t.Fatal("ordinary rotation invalidated a valid historical signature", v, err)
	}
}

func TestCustomerPackageAuditSnapshotRejectsInvalidClockAndCancellation(t *testing.T) {
	s := customerAuditFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if v, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", now, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{}); !errors.Is(err, packageapp.ErrValidation) || v != nil {
			t.Fatal("invalid audit clock", v, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readCustomerPackageAuditTx(ctx, tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{}); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("canceled audit snapshot returned summary", v, err)
	}
}

func TestCustomerPackageAuditSnapshotBoundsCanonicalMetadataStructure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]any
		valid    bool
	}{
		{"exact depth", nestedCustomerAuditMetadata(31), true},
		{"excess depth", nestedCustomerAuditMetadata(32), false},
		{"exact items", map[string]any{"items": make([]string, 4096)}, true},
		{"excess items", map[string]any{"items": make([]string, 4097)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := customerAuditFixture(t)
			if err := app.ExecuteUnitOfWork(t.Context(), s, func(ctx context.Context, repos app.Repositories) error {
				_, err := repos.Audit.Append(ctx, domain.AuditChainEntry{ID: "bounded_metadata", TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "subject", ActorType: "api_key", ActorID: "caller", OccurredAt: customerGovernanceNow, Metadata: tc.metadata})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			budget := &customerSnapshotBudget{remainingBytes: 1024}
			v, err := readCustomerPackageAuditTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, budget, customerAuditHasher{}, localed25519.PayloadVerifier{})
			if tc.valid {
				if err != nil || v["result"] != "passed" || v["latest_sequence"] != int64(131) {
					t.Fatal("valid bounded canonical metadata rejected", v, err)
				}
			} else if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != 1024 {
				t.Fatal("unbounded canonical metadata returned a summary", v, budget, err)
			}
		})
	}
}

func nestedCustomerAuditMetadata(depth int) map[string]any {
	var value any = "leaf"
	for range depth {
		value = map[string]any{"child": value}
	}
	return value.(map[string]any)
}

func TestCustomerPackageAuditSnapshotKeepsViewAndDoesNotTakeWriterLocks(t *testing.T) {
	s := customerAuditFixture(t)
	tx := customerCatalogReadTx(t, s)
	read := func() (map[string]any, error) {
		return readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{})
	}
	before, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE signatures SET value='tampered' WHERE id='audit_signature'`); err != nil {
		t.Fatal(err)
	}
	still, err := read()
	if err != nil || !reflect.DeepEqual(before, still) {
		t.Fatal("mixed audit/signature snapshot", still, err)
	}
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) })
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtext('tenant')); SELECT id FROM audit_chain_entries WHERE tenant_id='tenant' FOR UPDATE; SELECT id FROM merkle_batches WHERE id='audit_batch' FOR UPDATE; SELECT id FROM signatures WHERE id='audit_signature' FOR UPDATE; SELECT id FROM signing_keys WHERE id='audit_key' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	after, err := readCustomerPackageAuditTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 1024}, customerAuditHasher{}, localed25519.PayloadVerifier{})
	if err != nil || after["result"] != "failed" {
		t.Fatal("read-only verifier acquired a writer fence or row lock", after, err)
	}
}
