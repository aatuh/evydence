package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func customerReadinessFixture(t *testing.T) *Store {
	t.Helper()
	s := customerProfileFixture(t)
	for _, sql := range []string{
		`UPDATE redaction_profiles SET excluded_fields=ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'] WHERE id='profile'`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref,metadata) VALUES('scan_source','tenant','product','release','vulnerability_scan','private-title-marker','test','2026-10-01T00:00:00Z','evidence.v1','sha256:scan','sha256:scan','json','L2','pending','private-storage-marker','{"token":"private-token-marker"}')`,
		`INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings) VALUES('scan','tenant','scan_source','release','private-scanner-marker','private-target-marker','{}','[{"id":"finding","vulnerability":"CVE-1","severity":"critical","state":"open","private":"private-finding-marker"}]')`,
		`INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,impact_statement,customer_visible,internal_notes,source,schema_version,created_at) VALUES('decision','tenant','finding','scan','release','CVE-1','affected','triaged','',true,'private-notes-marker','manual','decision.v1','2026-10-01T00:00:00Z'),('foreign_decision','foreign_tenant','finding','scan','release','CVE-1','affected','','',true,'private-notes-marker','manual','decision.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO exceptions(id,tenant_id,release_id,reason,owner,expires_at,approved,approved_by,approved_at) VALUES('exception','tenant','release','private-reason-marker','private-owner-marker','2026-10-04T13:00:00Z',true,'private-approver-marker','2026-10-01T00:00:00Z'),('incomplete','tenant','release','','','2026-10-04T13:00:00Z',false,NULL,NULL),('foreign_exception','foreign_tenant','release','','','2026-10-04T13:00:00Z',false,NULL,NULL)`,
		`INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at) VALUES('package','tenant','product','release','profile','private-package-title-marker','generated','{"token":"private-manifest-marker"}','sha256:package','2026-10-04T13:00:00Z','package.v1','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func readinessCheck(t *testing.T, values []packagedomain.PolicyCheckSnapshot, name string) packagedomain.PolicyCheckSnapshot {
	t.Helper()
	for _, v := range values {
		if v.Name == name {
			return v
		}
	}
	t.Fatal("missing readiness check", name)
	return packagedomain.PolicyCheckSnapshot{}
}

func TestCustomerPackageReadinessSnapshotSharesRiskPolicyAndClock(t *testing.T) {
	s := customerReadinessFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before := budget.remainingBytes
	checks, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := readReleaseReadinessSnapshotTx(t.Context(), tx, "tenant", "release", customerGovernanceNow)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(facts, customerGovernanceNow)
	if err != nil || len(checks) != len(evaluation.Checks) {
		t.Fatal("canonical risk evaluation changed", err)
	}
	for i, v := range evaluation.Checks {
		want := packagedomain.PolicyCheckSnapshot{Name: v.Name, Result: v.Result, Severity: v.Severity, Missing: v.Missing, Explanation: v.Explanation, Remediation: v.Remediation}
		if !reflect.DeepEqual(checks[i], want) {
			t.Fatal("package duplicated or changed readiness rules", checks[i], want)
		}
	}
	body, err := json.Marshal(checks)
	if err != nil || strings.Contains(string(body), "private-") || strings.Contains(string(body), "foreign_") || before-budget.remainingBytes != len(body) {
		t.Fatalf("unsafe/uncharged checks: %s budget=%d err=%v", body, budget.remainingBytes, err)
	}
	if v := readinessCheck(t, checks, "critical_exploitable_blocks_release"); v.Result != "passed" {
		t.Fatal("valid exception did not apply at generation time", v)
	}
	if v := readinessCheck(t, checks, "package_redaction_profile_valid"); v.Result != "passed" {
		t.Fatal("valid package was not checked at generation time", v)
	}
	exact := &customerSnapshotBudget{remainingBytes: len(body)}
	if v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, exact); err != nil || !reflect.DeepEqual(v, checks) || exact.remainingBytes != 0 {
		t.Fatal("exact readiness byte budget rejected", v, exact, err)
	}
	for _, size := range []int{0, 1, len(body) - 1} {
		b := &customerSnapshotBudget{remainingBytes: size}
		if v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, b); !errors.Is(err, packageapp.ErrConflict) || v != nil || b.remainingBytes != size {
			t.Fatalf("partial over-budget checks=%#v budget=%d err=%v", v, b.remainingBytes, err)
		}
	}
	after, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow.Add(2*time.Hour), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || readinessCheck(t, after, "critical_exploitable_blocks_release").Result != "failed" || readinessCheck(t, after, "package_redaction_profile_valid").Result != "failed" {
		t.Fatal("readiness ignored fixed clock/expiry", after, err)
	}
	if v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 0}); err != nil || v != nil {
		t.Fatal("product-only package acquired release readiness", v, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM policy_evaluations)+(SELECT count(*) FROM verification_results)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("readiness write effects=%d err=%v", effects, err)
	}
}

type customerReadinessWatchTx struct {
	pgx.Tx
	largest int
}

func (w *customerReadinessWatchTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := w.Tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return customerReadinessWatchRows{Rows: rows, watch: w}, nil
}

type customerReadinessWatchRows struct {
	pgx.Rows
	watch *customerReadinessWatchTx
}

func (r customerReadinessWatchRows) Scan(dest ...any) error {
	if err := r.Rows.Scan(dest...); err != nil {
		return err
	}
	for _, value := range dest {
		if v, ok := value.(*string); ok && len(*v) > r.watch.largest {
			r.watch.largest = len(*v)
		}
	}
	return nil
}

func TestCustomerPackageReadinessSnapshotBoundsIDsBeforeTransfer(t *testing.T) {
	s := customerReadinessFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"decision bytes", `UPDATE vulnerability_decisions SET id=repeat('é',513) WHERE id='decision'`, `UPDATE vulnerability_decisions SET id='decision' WHERE tenant_id='tenant' AND length(id)=513`},
		{"package bytes", `UPDATE customer_security_packages SET id=repeat('x',8192),expires_at='2026-10-04T12:00:00Z' WHERE id='package'`, `UPDATE customer_security_packages SET id='package',expires_at='2026-10-04T13:00:00Z' WHERE tenant_id='tenant'`},
		{"exception bytes", `UPDATE exceptions SET id=repeat('x',1025) WHERE id='incomplete'`, `UPDATE exceptions SET id='incomplete' WHERE tenant_id='tenant' AND length(id)=1025`},
		{"malformed findings", `UPDATE vulnerability_scans SET findings='{}' WHERE id='scan'`, `UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-1","severity":"critical","state":"open"}]' WHERE id='scan'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerReadinessWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
			if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.largest > 1024 {
				t.Fatalf("invalid readiness transferred: value=%#v bytes=%d budget=%d err=%v", v, tx.largest, budget.remainingBytes, err)
			}
		})
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET id=repeat('x',1024) WHERE id='decision'`); err != nil {
		t.Fatal(err)
	}
	tx := &customerReadinessWatchTx{Tx: customerCatalogReadTx(t, s)}
	if v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 10}); !errors.Is(err, packageapp.ErrConflict) || v != nil || tx.largest != 0 {
		t.Fatalf("ID byte budget ignored before transfer: value=%#v bytes=%d err=%v", v, tx.largest, err)
	}
}

func TestCustomerPackageReadinessSnapshotCountsOnlyCoherentPackages(t *testing.T) {
	s := customerReadinessFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE customer_security_packages SET product_id='sibling',expires_at='2026-10-04T12:00:00Z' WHERE id='package'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageReadinessTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	check := readinessCheck(t, v, "package_redaction_profile_valid")
	if check.Result != "passed" || check.Severity != "medium" || len(check.Missing) != 0 {
		t.Fatal("package with incoherent product/release affected selected scope", check)
	}
}

func TestCustomerPackageReadinessSnapshotBoundsIdentifierCount(t *testing.T) {
	s := customerReadinessFixture(t)
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM customer_security_packages WHERE id='package'; UPDATE vulnerability_decisions SET impact_statement='Reviewed' WHERE id='decision'; INSERT INTO exceptions(id,tenant_id,release_id,reason,owner,expires_at,approved) SELECT 'overflow_'||n,'tenant','release','','','2026-10-04T13:00:00Z',false FROM generate_series(1,4096)n`); err != nil {
		t.Fatal(err)
	}
	tx := &customerReadinessWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
	if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.largest != 0 {
		t.Fatalf("overflow identifiers transferred: value=%#v bytes=%d budget=%d err=%v", v, tx.largest, budget.remainingBytes, err)
	}
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM exceptions WHERE id='overflow_4096'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageReadinessTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(readinessCheck(t, v, "exceptions_require_owner_reason_expiry_and_approval").Missing) != maxReadinessIDs {
		t.Fatal("exact identifier limit rejected or truncated", err)
	}
}

func TestCustomerPackageReadinessSnapshotKeepsViewAndDoesNotTakeWriterFence(t *testing.T) {
	s := customerReadinessFixture(t)
	tx := customerCatalogReadTx(t, s)
	read := func(tx pgx.Tx) ([]packagedomain.PolicyCheckSnapshot, error) {
		return readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	}
	before, err := read(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET impact_statement='Reviewed' WHERE id='decision'; UPDATE exceptions SET approved=false WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	still, err := read(tx)
	if err != nil || !reflect.DeepEqual(before, still) {
		t.Fatal("mixed readiness view", still, err)
	}
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) })
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT id FROM releases WHERE id='release' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	after, err := readCustomerPackageReadinessTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || readinessCheck(t, after, "critical_exploitable_blocks_release").Result != "failed" || len(readinessCheck(t, after, "customer_visible_decisions_require_statements").Missing) != 0 {
		t.Fatal("readiness blocked by fence or failed to see new commit", after, err)
	}
}

func TestCustomerPackageReadinessSnapshotRejectsForeignRootsAndInvalidClock(t *testing.T) {
	s := customerReadinessFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][3]string{{"tenant", "product", "sibling_release"}, {"tenant", "foreign_product", ""}, {"foreign_tenant", "product", "release"}} {
		if v, err := readCustomerPackageReadinessTx(t.Context(), tx, scope[0], scope[1], scope[2], customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrNotFound) || v != nil {
			t.Fatal("foreign readiness scope", v, err)
		}
	}
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if v, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", now, &customerSnapshotBudget{remainingBytes: 100}); !errors.Is(err, packageapp.ErrValidation) || v != nil {
			t.Fatal("invalid readiness clock", v, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readCustomerPackageReadinessTx(ctx, tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: 100}); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("canceled readiness returned data", v, err)
	}
}
