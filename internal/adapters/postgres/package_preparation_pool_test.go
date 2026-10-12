package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestPackagePreparationReadsCommittedDataWhenCommandPoolIsFull(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	config := store.pool.Config()
	config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	store.pool.Close()
	store.pool = pool
	identity := postgresIdentitySetup(store, "test-pepper")
	tenant, _, _, err := identity.BootstrapTenant(t.Context(), "Preparation", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug) VALUES('preparation-product',$1,'Preparation','preparation');`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('preparation-release',$1,'preparation-product','committed','draft')`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES('preparation-profile',$1,'Public',ARRAY['document'],ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'],'profile.v1',now())`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	reader, err := NewCustomerPackageCreationSnapshotReader(store, postgresCustomerFixtureHasher{}, localed25519.PayloadVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	var public string
	if err := pool.QueryRow(t.Context(), `SELECT public_key FROM signing_keys WHERE tenant_id=$1 AND status='active'`, tenant.ID).Scan(&public); err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(public)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := tx.Exec(t.Context(), `UPDATE releases SET version='uncommitted' WHERE id='preparation-release'`); err != nil {
		t.Fatal(err)
	}
	if pool.Stat().AcquiredConns() != pool.Config().MaxConns {
		t.Fatal("command pool is not saturated")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	now := time.Now().UTC()
	snapshot, err := store.ReadReleaseBundleSnapshot(ctx, tenant.ID, "preparation-release", now)
	if err != nil || snapshot.TenantID != tenant.ID || snapshot.ReleaseVersion != "committed" {
		t.Fatalf("committed snapshot under pool exhaustion: version=%q err=%v", snapshot.ReleaseVersion, err)
	}
	if _, err := store.ReadReleaseBundleSnapshot(ctx, "foreign", "preparation-release", now); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatalf("foreign snapshot err=%v", err)
	}
	export, err := store.ReadEvidenceBundleSnapshot(ctx, tenant.ID, "preparation-release", now)
	if err != nil || export.TenantID != tenant.ID || export.ProductID != "preparation-product" || len(export.Evidence) != 0 {
		t.Fatalf("evidence export under pool exhaustion: err=%v", err)
	}
	if _, err := store.ReadEvidenceBundleSnapshot(ctx, "foreign", "preparation-release", now); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatalf("foreign evidence export err=%v", err)
	}
	view, err := reader.ReadCustomerPackageCreationSnapshot(ctx, tenant.ID, "preparation-product", "preparation-release", "preparation-profile", now)
	if err != nil || view.Snapshot.TenantID != tenant.ID || view.Snapshot.Release["version"] != "committed" {
		t.Fatalf("customer snapshot under pool exhaustion: err=%v", err)
	}
	if _, err := reader.ReadCustomerPackageCreationSnapshot(ctx, "foreign", "preparation-product", "preparation-release", "preparation-profile", now); !errors.Is(err, packageapp.ErrNotFound) {
		t.Fatalf("foreign customer snapshot err=%v", err)
	}
	request := packageapp.PackageSigningRequest{TenantID: tenant.ID, SubjectType: "release_bundle", SubjectID: "prepared-bundle", PayloadHash: "sha256:prepared", CreatedAt: now}
	signature, err := store.SignPackage(ctx, request)
	if err != nil || signature.TenantID != tenant.ID || signature.SubjectID != request.SubjectID {
		t.Fatalf("signing under pool exhaustion: err=%v", err)
	}
	value, err := base64.RawStdEncoding.Strict().DecodeString(signature.Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), []byte(request.PayloadHash), value) {
		t.Fatal("prepared signature is not valid")
	}
	request.TenantID = "foreign"
	if _, err := store.SignPackage(ctx, request); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatalf("foreign signing err=%v", err)
	}
	if config := store.packageReadPool.Config(); config.MaxConns > 4 || config.MinConns != 0 || config.MinIdleConns != 0 {
		t.Fatal("package preparation has unbounded or eagerly reserved read capacity")
	}
	var readOnly string
	if err := store.packageReadPool.QueryRow(ctx, `SHOW default_transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		t.Fatalf("preparation pool is not read-only: setting=%q err=%v", readOnly, err)
	}
	if store.packageReadPool.Stat().AcquiredConns() != 0 {
		t.Fatal("package preparation retained a connection")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := store.ReadReleaseBundleSnapshot(canceled, tenant.ID, "preparation-release", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot err=%v", err)
	}
	if _, err := store.SignPackage(canceled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signing err=%v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if store.packageReadPool.Stat().TotalConns() != 0 || pool.Stat().TotalConns() != 0 {
		t.Fatal("Store.Close retained database connections")
	}
}
