package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func customerProfileFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO redaction_profiles(id,tenant_id,name,description,allowed_types,excluded_fields,schema_version,created_at) VALUES
	 ('profile','tenant','Customer','Public description',ARRAY['build','sbom'],ARRAY['token','private_key'],'redaction.v1','2026-10-01T12:34:56.123456Z'),
	 ('other_profile','tenant',repeat('x',65537),'',ARRAY['sbom'],'{}','redaction.v1','2026-10-01T00:00:00Z'),
	 ('foreign_profile','foreign_tenant','private-foreign-marker','',ARRAY['sbom'],'{}','redaction.v1','2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCustomerPackageProfileSnapshotPreservesSelectedPolicy(t *testing.T) {
	s := customerProfileFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	p, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", "profile", budget)
	want := packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", Description: "Public description", AllowedTypes: []string{"build", "sbom"}, ExcludedFields: []string{"token", "private_key"}, SchemaVersion: "redaction.v1", CreatedAt: time.Date(2026, 10, 1, 12, 34, 56, 123456000, time.UTC)}
	if err != nil || !reflect.DeepEqual(p, want) || tx.privateFound || budget.remainingBytes >= packageapp.MaxCustomerPackageManifestBytes {
		t.Fatalf("selected policy=%#v budget=%d private=%v err=%v", p, budget.remainingBytes, tx.privateFound, err)
	}
	var written packagedomain.RedactionProfile
	err = app.ExecuteUnitOfWork(t.Context(), s, func(ctx context.Context, repos app.Repositories) error {
		var err error
		written, err = repos.Packages.(interface {
			GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
		}).GetCustomerPackageRedactionProfile(ctx, "tenant", "profile")
		return err
	})
	if err != nil || !reflect.DeepEqual(p, written) {
		t.Fatalf("read/write policy mismatch: read=%#v write=%#v err=%v", p, written, err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - budget.remainingBytes
	exact := &customerSnapshotBudget{remainingBytes: used}
	if v, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", "profile", exact); err != nil || !reflect.DeepEqual(v, want) || exact.remainingBytes != 0 {
		t.Fatalf("exact policy byte budget rejected: %#v budget=%d err=%v", v, exact.remainingBytes, err)
	}
	for _, remaining := range []int{0, 1, used - 1} {
		small := &customerSnapshotBudget{remainingBytes: remaining}
		watch := &customerMetadataWatchTx{Tx: tx.Tx}
		v, err := readCustomerPackageProfileTx(t.Context(), watch, "tenant", "product", "release", "profile", small)
		if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) || small.remainingBytes != remaining || watch.largest != 0 {
			t.Fatalf("over-budget policy transferred: value=%#v bytes=%d remaining=%d err=%v", v, watch.largest, small.remainingBytes, err)
		}
	}
}

func TestCustomerPackageProfileSnapshotRejectsUnusablePolicyWithoutConsumption(t *testing.T) {
	s := customerProfileFixture(t)
	for _, tc := range []struct{ sql, restore string }{
		{`UPDATE redaction_profiles SET name='' WHERE id='profile'`, `UPDATE redaction_profiles SET name='Customer' WHERE id='profile'`},
		{`UPDATE redaction_profiles SET schema_version='' WHERE id='profile'`, `UPDATE redaction_profiles SET schema_version='redaction.v1' WHERE id='profile'`},
		{`UPDATE redaction_profiles SET allowed_types='{}' WHERE id='profile'`, `UPDATE redaction_profiles SET allowed_types=ARRAY['build','sbom'] WHERE id='profile'`},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageProfileTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", "profile", budget)
			if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatalf("unusable policy=%#v budget=%d err=%v", v, budget.remainingBytes, err)
			}
		})
	}
}

func TestCustomerPackageProfileSnapshotRejectsMalformedBeforeTransfer(t *testing.T) {
	s := customerProfileFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"name", `UPDATE redaction_profiles SET name=repeat('x',65537) WHERE id='profile'`, `UPDATE redaction_profiles SET name='Customer' WHERE id='profile'`},
		{"description", `UPDATE redaction_profiles SET description=repeat('x',65537) WHERE id='profile'`, `UPDATE redaction_profiles SET description='Public description' WHERE id='profile'`},
		{"schema", `UPDATE redaction_profiles SET schema_version=repeat('x',1025) WHERE id='profile'`, `UPDATE redaction_profiles SET schema_version='redaction.v1' WHERE id='profile'`},
		{"allowed count", `UPDATE redaction_profiles SET allowed_types=ARRAY(SELECT 'sbom' FROM generate_series(1,1025)) WHERE id='profile'`, `UPDATE redaction_profiles SET allowed_types=ARRAY['build','sbom'] WHERE id='profile'`},
		{"excluded count", `UPDATE redaction_profiles SET excluded_fields=ARRAY(SELECT 'token' FROM generate_series(1,1025)) WHERE id='profile'`, `UPDATE redaction_profiles SET excluded_fields=ARRAY['token','private_key'] WHERE id='profile'`},
		{"allowed item", `UPDATE redaction_profiles SET allowed_types=ARRAY[repeat('x',1025)] WHERE id='profile'`, `UPDATE redaction_profiles SET allowed_types=ARRAY['build','sbom'] WHERE id='profile'`},
		{"excluded item", `UPDATE redaction_profiles SET excluded_fields=ARRAY[repeat('x',1025)] WHERE id='profile'`, `UPDATE redaction_profiles SET excluded_fields=ARRAY['token','private_key'] WHERE id='profile'`},
		{"null item", `UPDATE redaction_profiles SET allowed_types=ARRAY['sbom',NULL] WHERE id='profile'`, `UPDATE redaction_profiles SET allowed_types=ARRAY['build','sbom'] WHERE id='profile'`},
		{"allowed dimensions", `UPDATE redaction_profiles SET allowed_types=ARRAY[['build','sbom']] WHERE id='profile'`, `UPDATE redaction_profiles SET allowed_types=ARRAY['build','sbom'] WHERE id='profile'`},
		{"excluded dimensions", `UPDATE redaction_profiles SET excluded_fields=ARRAY[['token','private_key']] WHERE id='profile'`, `UPDATE redaction_profiles SET excluded_fields=ARRAY['token','private_key'] WHERE id='profile'`},
		{"infinite time", `UPDATE redaction_profiles SET created_at='infinity' WHERE id='profile'`, `UPDATE redaction_profiles SET created_at='2026-10-01T12:34:56.123456Z' WHERE id='profile'`},
		{"time range", `UPDATE redaction_profiles SET created_at='10000-01-01T00:00:00Z' WHERE id='profile'`, `UPDATE redaction_profiles SET created_at='2026-10-01T12:34:56.123456Z' WHERE id='profile'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", "profile", budget)
			if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) || tx.largest != 0 || tx.privateFound || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatalf("invalid policy transferred: value=%#v bytes=%d budget=%d err=%v", v, tx.largest, budget.remainingBytes, err)
			}
			err = app.ExecuteUnitOfWork(t.Context(), s, func(ctx context.Context, repos app.Repositories) error {
				v, err := repos.Packages.(interface {
					GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
				}).GetCustomerPackageRedactionProfile(ctx, "tenant", "profile")
				if !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
					t.Fatalf("write policy did not reject same malformed data: %#v err=%v", v, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCustomerPackageProfileSnapshotRejectsForeignAndInvalidScope(t *testing.T) {
	s := customerProfileFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][4]string{{"tenant", "product", "release", "foreign_profile"}, {"foreign_tenant", "foreign_product", "foreign_release", "profile"}, {"tenant", "product", "sibling_release", "profile"}, {"tenant", "foreign_product", "", "profile"}, {"tenant", "product", "", "missing"}} {
		budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		v, err := readCustomerPackageProfileTx(t.Context(), tx, scope[0], scope[1], scope[2], scope[3], budget)
		if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
			t.Fatalf("foreign scope policy=%#v budget=%d err=%v", v, budget.remainingBytes, err)
		}
	}
	for _, id := range []string{"", " profile", "\u2003profile", strings.Repeat("é", 513), "profile\x00", string([]byte{0xff})} {
		if _, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", id, &customerSnapshotBudget{remainingBytes: 100}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatal("invalid raw profile accepted", id, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readCustomerPackageProfileTx(ctx, tx, "tenant", "product", "release", "profile", &customerSnapshotBudget{remainingBytes: 100}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCustomerPackageProfileSnapshotKeepsViewWithoutWriterLocks(t *testing.T) {
	s := customerProfileFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", "profile", budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE redaction_profiles SET description='Changed',allowed_types=ARRAY['build'] WHERE id='profile'`); err != nil {
		t.Fatal(err)
	}
	still, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "release", "profile", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, still) {
		t.Fatal("mixed policy view", still, err)
	}
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) })
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT id FROM redaction_profiles WHERE id='profile' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	after, err := readCustomerPackageProfileTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", "profile", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || after.Description != "Changed" || !reflect.DeepEqual(after.AllowedTypes, []string{"build"}) {
		t.Fatal("snapshot took writer fence or row locks", after, err)
	}
	var effects int
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("policy read effects=%d err=%v", effects, err)
	}
}

func TestCustomerPackageProfileSnapshotAcceptsExactBoundsAndEmptyExclusions(t *testing.T) {
	s := customerProfileFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE redaction_profiles SET name=repeat('x',65536),description=repeat('x',65536),allowed_types=ARRAY(SELECT repeat('x',1024) FROM generate_series(1,1024)),excluded_fields='{}' WHERE id='profile'`); err != nil {
		t.Fatal(err)
	}
	p, err := readCustomerPackageProfileTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", "profile", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(p.Name) != packageapp.MaxRedactionProfileTextBytes || len(p.Description) != packageapp.MaxRedactionProfileTextBytes || len(p.AllowedTypes) != packageapp.MaxRedactionProfileEntries || len(p.AllowedTypes[0]) != packageapp.MaxRedactionProfileEntryBytes || len(p.ExcludedFields) != 0 {
		t.Fatal("exact profile bound rejected", err)
	}
}
