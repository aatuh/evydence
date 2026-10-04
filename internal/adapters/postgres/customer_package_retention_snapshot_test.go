package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func customerRetentionFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	for _, sql := range []string{
		`INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,object_key,mode,retention_days,status,schema_version,created_at)
		 VALUES('a_configured','tenant','Configured','','','GOVERNANCE',1,'configured','retention.v2','2026-10-01T12:34:56.123456Z'),
		 ('b_expired','tenant','Expired','','','GOVERNANCE',1,'verified','retention.v2','2026-10-01T12:34:56.123456Z'),
		 ('c_fresh','tenant','Fresh','private-prefix-marker','private-object-key-marker','COMPLIANCE',30,'verified','retention.v2','2026-10-01T12:34:56.123456Z'),
		 ('foreign_policy','foreign_tenant','Foreign','','','GOVERNANCE',1,'configured','retention.v2',now())`,
		`UPDATE object_retention_policies SET require_legal_hold=true,verification_hash='sha256:observation',verification_provider='minio',verification_bucket='private-bucket-marker',verification_mode='COMPLIANCE',verification_retention_days=30,verification_legal_hold=true,
		 verification_checks='[{"name":"z","result":"passed","detail":"recorded","x-private":{"token":"private-check-extension-marker"}},{"name":"a","result":"passed"}]',verification_limitations=ARRAY['recorded scope'] WHERE id='c_fresh'`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET verification_expires_at=$1 WHERE id='b_expired'`, customerGovernanceNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET verified_at=$1,verification_observed_at=$2,verification_expires_at=$3 WHERE id='c_fresh'`, customerGovernanceNow, customerGovernanceNow.Add(-time.Hour), customerGovernanceNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBundleRetentionFactsStripPrivateExtensionsBeforeDriver(t *testing.T) {
	s := customerRetentionFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	values, err := readBundleRetentionPolicies(t.Context(), tx, "tenant", packageapp.MaxBundleSnapshotRows)
	if err != nil || len(values) != 3 || values[2].ID != "c_fresh" || values[2].ObjectPrefix != "configured" || values[2].ObjectKey != "configured" || values[2].VerificationBucket != "" || len(values[2].VerificationChecks) != 2 || values[2].VerificationChecks[0].Name != "z" || tx.privateFound {
		t.Fatalf("private retention facts crossed driver: values=%#v private=%v err=%v", values, tx.privateFound, err)
	}
}

func TestCustomerPackageRetentionSnapshotMatchesCanonicalPublicProofs(t *testing.T) {
	s := customerRetentionFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 1, 12, 34, 56, 123456000, time.UTC)
	expired, future, observed, hold := customerGovernanceNow, customerGovernanceNow.Add(time.Hour), customerGovernanceNow.Add(-time.Hour), true
	want := verificationapp.ObjectLockProofs([]verificationdomain.ObjectRetentionPolicy{
		{ID: "a_configured", TenantID: "tenant", Name: "Configured", Mode: "GOVERNANCE", RetentionDays: 1, Status: "configured", CreatedAt: created},
		{ID: "b_expired", TenantID: "tenant", Name: "Expired", Mode: "GOVERNANCE", RetentionDays: 1, Status: "verified", VerificationExpiresAt: &expired, CreatedAt: created},
		{ID: "c_fresh", TenantID: "tenant", Name: "Fresh", ObjectPrefix: "private-prefix-marker", ObjectKey: "private-object-key-marker", RequireLegalHold: true, Mode: "COMPLIANCE", RetentionDays: 30, Status: "verified", CreatedAt: created, VerifiedAt: &expired, VerificationHash: "sha256:observation", VerificationProvider: "minio", VerificationBucket: "private-bucket-marker", VerificationMode: "COMPLIANCE", VerificationRetentionDays: 30, VerificationLegalHold: &hold, VerificationObservedAt: &observed, VerificationExpiresAt: &future, VerificationChecks: []verificationdomain.VerifyCheck{{Name: "z", Result: "passed", Detail: "recorded"}, {Name: "a", Result: "passed"}}, VerificationLimitations: []string{"recorded scope"}},
	}, customerGovernanceNow)
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("canonical proof shape changed: got=%#v want=%#v", v, want)
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), "private-") || strings.Contains(string(body), "foreign_policy") || tx.privateFound || budget.remainingBytes >= packageapp.MaxCustomerPackageManifestBytes {
		t.Fatalf("nonpublic data crossed driver: body=%s private=%v budget=%d", body, tx.privateFound, budget.remainingBytes)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - budget.remainingBytes
	exact := &customerSnapshotBudget{remainingBytes: used}
	if same, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, exact); err != nil || !reflect.DeepEqual(same, v) || exact.remainingBytes != 0 {
		t.Fatalf("exact retention budget=%d err=%v", exact.remainingBytes, err)
	}
	for _, remaining := range []int{0, used - 1} {
		b := &customerSnapshotBudget{remainingBytes: remaining}
		if partial, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, b); !errors.Is(err, packageapp.ErrConflict) || partial != nil || b.remainingBytes != remaining {
			t.Fatalf("partial retention result=%#v budget=%d err=%v", partial, b.remainingBytes, err)
		}
	}
	product, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(product, v) {
		t.Fatalf("tenant-wide observation metadata changed in product-only package: %#v err=%v", product, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM verification_results)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("read persisted effects=%d err=%v", effects, err)
	}
}

func TestCustomerPackageRetentionSnapshotRejectsMalformedBeforeTransfer(t *testing.T) {
	s := customerRetentionFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"multidimensional limitations", `UPDATE object_retention_policies SET verification_limitations=ARRAY[['a','b'],['c','d']] WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_limitations='{}' WHERE id='c_fresh'`},
		{"null limitation", `UPDATE object_retention_policies SET verification_limitations=ARRAY[NULL::text] WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_limitations='{}' WHERE id='c_fresh'`},
		{"malformed checks", `UPDATE object_retention_policies SET verification_checks='{}' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"null checks", `UPDATE object_retention_policies SET verification_checks='null' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"nested private check", `UPDATE object_retention_policies SET verification_checks='[{"name":"provider","detail":{"token":"private-nested-marker"}}]' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"null check", `UPDATE object_retention_policies SET verification_checks='[null]' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"source byte limit", `UPDATE object_retention_policies SET verification_checks=jsonb_build_array(jsonb_build_object('name','provider','detail',repeat('x',8388609))) WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"check count", `UPDATE object_retention_policies SET verification_checks=(SELECT jsonb_agg(jsonb_build_object('name','provider','result','passed')) FROM generate_series(1,4097)) WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='c_fresh'`},
		{"limitation count", `UPDATE object_retention_policies SET verification_limitations=ARRAY(SELECT 'scope' FROM generate_series(1,4097)) WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_limitations='{}' WHERE id='c_fresh'`},
		{"name bytes", `UPDATE object_retention_policies SET name=repeat('x',4097) WHERE id='c_fresh'`, `UPDATE object_retention_policies SET name='Fresh' WHERE id='c_fresh'`},
		{"negative retention", `UPDATE object_retention_policies SET retention_days=-1 WHERE id='c_fresh'`, `UPDATE object_retention_policies SET retention_days=30 WHERE id='c_fresh'`},
		{"infinite creation", `UPDATE object_retention_policies SET created_at='infinity' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET created_at=now() WHERE id='c_fresh'`},
		{"out of range expiry", `UPDATE object_retention_policies SET verification_expires_at='10000-01-01T00:00:00Z' WHERE id='c_fresh'`, `UPDATE object_retention_policies SET verification_expires_at=now() WHERE id='c_fresh'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			for _, bundle := range []bool{false, true} {
				tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
				budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
				if bundle {
					v, err := readBundleRetentionPolicies(t.Context(), tx, "tenant", packageapp.MaxBundleSnapshotRows)
					if !errors.Is(err, packageapp.ErrConflict) || v != nil {
						t.Fatalf("bundle malformed facts=%#v err=%v", v, err)
					}
				} else {
					v, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
					if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
						t.Fatalf("customer malformed proof=%#v budget=%d err=%v", v, budget.remainingBytes, err)
					}
				}
				if tx.privateFound || tx.largest != 0 {
					t.Fatalf("malformed facts transferred before rejection: private=%v bytes=%d", tx.privateFound, tx.largest)
				}
			}
		})
	}
}

func TestCustomerPackageRetentionSnapshotSharesCatalogViewAndDoesNotLockWriters(t *testing.T) {
	s := customerRetentionFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET name='After',status='not_verified' WHERE id='c_fresh'`); err != nil {
		t.Fatal(err)
	}
	again, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, again) {
		t.Fatalf("mixed retention view=%#v err=%v", again, err)
	}
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE`, `SELECT id FROM object_retention_policies WHERE id='c_fresh' FOR UPDATE`} {
		if _, err := writer.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	after, err := readCustomerPackageRetentionTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || after[2]["name"] != "After" || after[2]["status"] != "not_verified" {
		t.Fatalf("retention read blocked or missed committed view=%#v err=%v", after, err)
	}
}

func TestCustomerPackageRetentionSnapshotRejectsForeignScopeAndInvalidClock(t *testing.T) {
	s := customerRetentionFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"foreign_tenant", "product", "release"}, {"tenant", "product", "sibling_release"}} {
		budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		if v, err := readCustomerPackageRetentionTx(t.Context(), tx, scope[0], scope[1], scope[2], customerGovernanceNow, budget); !errors.Is(err, packageapp.ErrNotFound) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
			t.Fatalf("foreign roots returned observations=%#v err=%v", v, err)
		}
	}
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if v, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", now, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) || v != nil {
			t.Fatal("invalid generation clock", v, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readCustomerPackageRetentionTx(ctx, tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("canceled proof returned", v, err)
	}
	foreign, err := readCustomerPackageRetentionTx(t.Context(), tx, "foreign_tenant", "foreign_product", "foreign_release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(foreign) != 1 || foreign[0]["id"] != "foreign_policy" {
		t.Fatalf("foreign tenant borrowed selected policies=%#v err=%v", foreign, err)
	}
}

func TestCustomerPackageRetentionSnapshotHonorsExactRowsAndCombinedDetailBounds(t *testing.T) {
	s := customerRetentionFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET verification_limitations='{}',verification_checks=(SELECT jsonb_agg(jsonb_build_object('name','check','result','limited')) FROM generate_series(1,4096)) WHERE id='c_fresh'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageRetentionTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v[2]["verification_checks"].([]map[string]any)) != 4096 {
		t.Fatalf("exact detail capacity rejected or truncated=%#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET verification_limitations=ARRAY['extra'] WHERE id='a_configured'`); err != nil {
		t.Fatal(err)
	}
	if v, err := readCustomerPackageRetentionTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrConflict) || v != nil {
		t.Fatal("combined detail capacity was ignored", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET verification_limitations='{}',verification_checks='[]'; INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,mode,retention_days,status,schema_version,created_at) SELECT 'capacity_'||lpad(n::text,4,'0'),'tenant','Capacity','','GOVERNANCE',1,'configured','retention.v2',now() FROM generate_series(1,4093)n`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageRetentionTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v) != 4096 {
		t.Fatalf("exact policy capacity rejected: len=%d err=%v", len(v), err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,mode,retention_days,status,schema_version,created_at) VALUES('capacity_overflow','tenant','Capacity','','GOVERNANCE',1,'configured','retention.v2',now())`); err != nil {
		t.Fatal(err)
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if v, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, budget); !errors.Is(err, packageapp.ErrConflict) || v != nil || tx.largest != 0 || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
		t.Fatalf("policy overflow transferred/truncated: len=%d budget=%d transfer=%d err=%v", len(v), budget.remainingBytes, tx.largest, err)
	}
}
