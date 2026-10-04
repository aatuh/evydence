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
	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func customerCreationSnapshotFixture(t *testing.T) *Store {
	t.Helper()
	s := customerGovernanceFixture(t)
	for _, sql := range []string{
		`INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES('profile','tenant','Public',ARRAY['sbom','vulnerability_scan','vex','openapi_contract','build','build_attestation','vulnerability_decision','document'],ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'],'profile.v1','2026-10-01T12:34:56.123456Z'),('foreign_profile','foreign_tenant','private-profile-marker',ARRAY['sbom'],'{}','profile.v1',now())`,
		`UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1","component":"component","severity":"critical","state":"open","private":"private-finding-marker"}]' WHERE id='vulnerability_scan_selected'`,
		`UPDATE build_runs SET outputs='[{"artifact_id":"artifact_build","digest":"sha256:build"}]',environment_hash='sha256:environment',parameters_hash='sha256:parameters' WHERE id='build'`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,type,title,source_system,observed_at,schema_version,payload_hash,payload_size,canonical_hash,canonicalization,trust_level,verification_status,payload_ref) VALUES('attestation_source','tenant','product','project','release','build','build_attestation','private-title-marker','test',now(),'evidence.v1','sha256:attestation',7,'sha256:attestation','json','L2','pending','private-payload-marker')`,
		`INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES('attestation','tenant','build','attestation_source','private-payload-marker','sha256:attestation',7,'application/json','test','["sha256:build"]',0,1,'structurally_valid','attestation.v1')`,
		`INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at,assurance_profile,schema_version) VALUES('receipt','tenant','build_attestation','attestation','not_evaluated','[]','2026-10-01T00:00:00Z','{"id":"recorded-profile"}','verification-result.v2.0.0')`,
		`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES('bundle','tenant','release','generated','{"token":"private-manifest-marker"}','sha256:bundle','[]')`,
		`INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,mode,retention_days,status,schema_version,created_at) VALUES('retention','tenant','Recorded','private-prefix-marker','GOVERNANCE',1,'configured','retention.v2','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

type customerSnapshotBeginFunc func(context.Context, pgx.TxOptions) (pgx.Tx, error)

func (f customerSnapshotBeginFunc) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	return f(ctx, options)
}

type customerCreationReadWatchTx struct {
	pgx.Tx
	afterRoot          func()
	commitError        error
	cancel             context.CancelFunc
	commits, rollbacks int
	cleanupCanceled    bool
}

func (w *customerCreationReadWatchTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return customerCreationReadWatchRow{Row: w.Tx.QueryRow(ctx, sql, args...), watch: w}
}

type customerCreationReadWatchRow struct {
	pgx.Row
	watch *customerCreationReadWatchTx
}

func (r customerCreationReadWatchRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err == nil && r.watch.afterRoot != nil {
		callback := r.watch.afterRoot
		r.watch.afterRoot = nil
		callback()
	}
	return err
}
func (w *customerCreationReadWatchTx) Commit(ctx context.Context) error {
	w.commits++
	if w.cancel != nil {
		w.cancel()
	}
	if w.commitError != nil {
		return w.commitError
	}
	return w.Tx.Commit(ctx)
}
func (w *customerCreationReadWatchTx) Rollback(ctx context.Context) error {
	w.rollbacks++
	w.cleanupCanceled = ctx.Err() != nil
	return w.Tx.Rollback(ctx)
}

func newCustomerCreationSnapshotReader(t *testing.T, s *Store) *CustomerPackageCreationSnapshotReader {
	t.Helper()
	r, err := NewCustomerPackageCreationSnapshotReader(s, customerAuditHasher{}, localed25519.PayloadVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCustomerPackageCreationSnapshotContainsEveryPublicSection(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	r := newCustomerCreationSnapshotReader(t, s)
	begins := 0
	var watch *customerMetadataWatchTx
	r.beginner = customerSnapshotBeginFunc(func(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
		begins++
		if o.IsoLevel != pgx.RepeatableRead || o.AccessMode != pgx.ReadOnly {
			t.Fatal("snapshot is not read-only repeatable-read", o)
		}
		tx, err := s.pool.BeginTx(ctx, o)
		if err != nil {
			return nil, err
		}
		watch = &customerMetadataWatchTx{Tx: tx}
		return watch, nil
	})
	v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil {
		t.Fatal(err)
	}
	if begins != 1 || v.Profile.ID != "profile" || v.Profile.CreatedAt.Nanosecond() != 123456000 || v.Snapshot.SnapshotVersion != packageapp.CustomerPackageSnapshotVersion || v.Snapshot.TenantID != "tenant" || v.Snapshot.ProductID != "product" || v.Snapshot.ReleaseID != "release" || v.Snapshot.Product["id"] != "product" || v.Snapshot.Release["id"] != "release" {
		t.Fatal("scope/policy/view changed", begins, v)
	}
	for _, part := range []struct {
		rows []map[string]any
		id   string
	}{
		{v.Snapshot.SBOMs, "sbom_selected"}, {v.Snapshot.VulnerabilityScans, "vulnerability_scan_selected"}, {v.Snapshot.VEXDocuments, "vex_selected"}, {v.Snapshot.Decisions, "decision_selected"}, {v.Snapshot.Exceptions, "exception_release"}, {v.Snapshot.ObjectLockProofs, "retention"},
	} {
		if len(part.rows) != 1 || part.rows[0]["id"] != part.id {
			t.Fatal("public section missing or mis-scoped", part)
		}
	}
	if len(v.Snapshot.Approvals) != 2 || len(v.Snapshot.Waivers) != 2 || len(v.Snapshot.AnswerLibrary) != 3 || len(v.Snapshot.Artifacts) != 4 || len(v.Snapshot.Evidence) < 5 || len(v.Snapshot.ReadinessChecks) == 0 {
		t.Fatal("complete metadata inventory missing", v.Snapshot)
	}
	if v.Snapshot.Provenance["builds"].([]map[string]any)[0]["id"] != "build" || v.Snapshot.Provenance["build_attestations"].([]map[string]any)[0]["id"] != "attestation" || len(v.Snapshot.APIContracts["openapi_contracts"].([]map[string]any)) != 1 || len(v.Snapshot.APIContracts["contract_diffs"].([]map[string]any)) != 1 {
		t.Fatal("provenance/contracts missing", v.Snapshot)
	}
	verification := v.Snapshot.VerificationMaterial
	if verification["verification_results"].([]map[string]any)[0]["id"] != "receipt" || verification["release_bundles"].([]map[string]any)[0]["id"] != "bundle" || verification["audit_chain"].(map[string]any)["latest_sequence"] != int64(0) {
		t.Fatal("verification/audit summary missing", verification)
	}
	body, err := json.Marshal(v)
	if err != nil || strings.Contains(string(body), "private-") || strings.Contains(string(body), "foreign_") || watch.privateFound {
		t.Fatal("private or unrelated metadata crossed boundary", err, watch.privateFound)
	}
	var effects int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM policy_evaluations)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("snapshot read wrote records", effects, err)
	}
}

func TestCustomerPackageCreationSnapshotKeepsOneViewAcrossPolicyCatalogAndRetention(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	r := newCustomerCreationSnapshotReader(t, s)
	r.beginner = customerSnapshotBeginFunc(func(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
		tx, err := s.pool.BeginTx(ctx, o)
		if err != nil {
			return nil, err
		}
		return &customerCreationReadWatchTx{Tx: tx, afterRoot: func() {
			if _, err := s.pool.Exec(ctx, `UPDATE products SET name='After' WHERE id='product'; UPDATE redaction_profiles SET name='After' WHERE id='profile'; UPDATE object_retention_policies SET name='After' WHERE id='retention'`); err != nil {
				t.Fatal(err)
			}
		}}, nil
	})
	v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil || v.Profile.Name != "Public" || v.Snapshot.Product["name"] != "Product" || v.Snapshot.ObjectLockProofs[0]["name"] != "Recorded" {
		t.Fatal("mixed committed views", v, err)
	}
	r = newCustomerCreationSnapshotReader(t, s)
	v, err = r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil || v.Profile.Name != "After" || v.Snapshot.Product["name"] != "After" || v.Snapshot.ObjectLockProofs[0]["name"] != "After" {
		t.Fatal("fresh view missed committed changes", v, err)
	}
}

func TestCustomerPackageCreationSnapshotRejectsForeignAndMalformedSections(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	r := newCustomerCreationSnapshotReader(t, s)
	for _, coordinates := range [][4]string{{"tenant", "product", "sibling_release", "profile"}, {"foreign_tenant", "product", "release", "profile"}, {"tenant", "product", "release", "foreign_profile"}, {"tenant", "foreign_product", "", "profile"}} {
		v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), coordinates[0], coordinates[1], coordinates[2], coordinates[3], customerGovernanceNow)
		if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
			t.Fatal("foreign scope returned partial snapshot", v, err)
		}
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"catalog timestamp", `UPDATE products SET created_at='10000-01-01T00:00:00Z' WHERE id='product'`, `UPDATE products SET created_at=now() WHERE id='product'`},
		{"parsed timestamp", `UPDATE sboms SET created_at='10000-01-01T00:00:00Z' WHERE id='sbom_selected'`, `UPDATE sboms SET created_at=now() WHERE id='sbom_selected'`},
		{"release timestamp", `UPDATE releases SET frozen_at='10000-01-01T00:00:00Z' WHERE id='release'`, `UPDATE releases SET frozen_at='2026-10-02T12:34:56.123456Z' WHERE id='release'`},
		{"organization timestamp", `UPDATE organizations SET created_at='10000-01-01T00:00:00Z' WHERE id='org'`, `UPDATE organizations SET created_at=now() WHERE id='org'`},
		{"artifact timestamp", `UPDATE artifacts SET created_at='10000-01-01T00:00:00Z' WHERE id='artifact_build'`, `UPDATE artifacts SET created_at=now() WHERE id='artifact_build'`},
		{"scan timestamp", `UPDATE vulnerability_scans SET created_at='10000-01-01T00:00:00Z' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET created_at=now() WHERE id='vulnerability_scan_selected'`},
		{"VEX timestamp", `UPDATE vex_documents SET created_at='10000-01-01T00:00:00Z' WHERE id='vex_selected'`, `UPDATE vex_documents SET created_at=now() WHERE id='vex_selected'`},
		{"contract timestamp", `UPDATE openapi_contracts SET created_at='10000-01-01T00:00:00Z' WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET created_at=now() WHERE id='openapi_contract_selected'`},
		{"diff timestamp", `UPDATE contract_diffs SET created_at='10000-01-01T00:00:00Z' WHERE id='diff_selected'`, `UPDATE contract_diffs SET created_at=now() WHERE id='diff_selected'`},
		{"evidence", `UPDATE sboms SET spec_version=repeat('x',8388609) WHERE id='sbom_selected'`, `UPDATE sboms SET spec_version='1.6' WHERE id='sbom_selected'`},
		{"verification", `UPDATE verification_results SET checks='{}' WHERE id='receipt'`, `UPDATE verification_results SET checks='[]' WHERE id='receipt'`},
		{"retention", `UPDATE object_retention_policies SET verification_checks='{}' WHERE id='retention'`, `UPDATE object_retention_policies SET verification_checks='[]' WHERE id='retention'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
			if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
				t.Fatal("malformed section published partial result", v, err)
			}
		})
	}
	productOnly, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "", "profile", customerGovernanceNow)
	if err != nil || len(productOnly.Snapshot.Release) != 0 || len(productOnly.Snapshot.Artifacts) != 0 || productOnly.Snapshot.ReadinessChecks != nil || productOnly.Snapshot.SBOMs[0]["id"] != "sbom_unreleased" {
		t.Fatal("product-only snapshot selection changed", productOnly, err)
	}
}

func TestCustomerPackageCreationSnapshotBudgetSpansAllComponents(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	// Fill the evidence component nearly to its independent capacity. It must
	// still succeed alone, but cannot reuse bytes already spent on catalog and
	// the selected profile in the complete view.
	fieldLength := budget.remainingBytes / 2
	for _, sql := range []string{`UPDATE sboms SET spec_version=repeat('x',$1) WHERE id='sbom_selected'`, `UPDATE vex_documents SET version=repeat('y',$1) WHERE id='vex_selected'`} {
		if _, err := s.pool.Exec(t.Context(), sql, fieldLength); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); err != nil {
		t.Fatal("standalone section did not fit", err)
	}
	r := newCustomerCreationSnapshotReader(t, s)
	v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
		t.Fatal("component reset the shared byte budget", v, err)
	}
}

func TestCustomerPackageCreationSnapshotBoundsFinalContainerOverhead(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO tenants(id,name) VALUES('tenant','Tenant'); INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product'); INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES('profile','tenant','Public',ARRAY['sbom'],'{}','profile.v1','2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	r := newCustomerCreationSnapshotReader(t, s)
	baseline, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "", "profile", customerGovernanceNow)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(baseline.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Only these four parts consume selected metadata in this empty fixture.
	// The final JSON also carries static contract limitations and containers.
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	tx := customerCatalogReadTx(t, s)
	if _, err := readCustomerPackageProfileTx(t.Context(), tx, "tenant", "product", "", "profile", budget); err != nil {
		t.Fatal(err)
	}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "", budget); err != nil {
		t.Fatal(err)
	}
	if _, err := readCustomerPackageAuditTx(t.Context(), tx, "tenant", "product", "", customerGovernanceNow, budget, customerAuditHasher{}, localed25519.PayloadVerifier{}); err != nil {
		t.Fatal(err)
	}
	if _, err := readCustomerPackageRetentionTx(t.Context(), tx, "tenant", "product", "", customerGovernanceNow, budget); err != nil {
		t.Fatal(err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - budget.remainingBytes
	if len(body) <= used+1 {
		t.Fatal("fixture does not exercise final container overhead", len(body), used)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE products SET name=repeat('x',$1) WHERE id='product'`, packageapp.MaxCustomerPackageManifestBytes-len(body)+len("Product")+1); err != nil {
		t.Fatal(err)
	}
	var watch *customerCreationReadWatchTx
	r.beginner = customerSnapshotBeginFunc(func(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
		tx, err := s.pool.BeginTx(ctx, o)
		if err != nil {
			return nil, err
		}
		watch = &customerCreationReadWatchTx{Tx: tx}
		return watch, nil
	})
	v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "", "profile", customerGovernanceNow)
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) || watch.commits != 0 || watch.rollbacks != 1 {
		t.Fatal("oversized final view was committed or returned", watch, err)
	}
}

func TestCustomerPackageCreationSnapshotTransactionFailuresReturnNothing(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	failure := errors.New("injected transaction failure")
	for _, phase := range []string{"begin", "commit", "canceled commit"} {
		t.Run(phase, func(t *testing.T) {
			r := newCustomerCreationSnapshotReader(t, s)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var watch *customerCreationReadWatchTx
			r.beginner = customerSnapshotBeginFunc(func(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
				if phase == "begin" {
					return nil, failure
				}
				tx, err := s.pool.BeginTx(ctx, o)
				if err != nil {
					return nil, err
				}
				watch = &customerCreationReadWatchTx{Tx: tx, commitError: failure}
				if phase == "canceled commit" {
					watch.commitError = nil
					watch.cancel = cancel
				}
				return watch, nil
			})
			v, err := r.ReadCustomerPackageCreationSnapshot(ctx, "tenant", "product", "release", "profile", customerGovernanceNow)
			if phase == "canceled commit" {
				if err == nil {
					t.Fatal("canceled commit passed")
				}
			} else if !errors.Is(err, failure) {
				t.Fatal("lost transaction failure", err)
			}
			if !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) || watch != nil && (watch.commits != 1 || watch.rollbacks != 1 || watch.cleanupCanceled) {
				t.Fatal("failed read published snapshot or leaked transaction", v, watch, err)
			}
		})
	}
}

func TestCustomerPackageCreationSnapshotRejectsInvalidInputBeforeBegin(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	r := newCustomerCreationSnapshotReader(t, s)
	for _, tc := range []struct {
		tenant, product, release, profile string
		at                                time.Time
	}{
		{" tenant", "product", "release", "profile", customerGovernanceNow}, {"tenant", strings.Repeat("x", 1025), "release", "profile", customerGovernanceNow}, {"tenant", "product", "release", "", customerGovernanceNow}, {"tenant", "product", "release", "profile", time.Time{}}, {"tenant", "product", "release", "profile", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		r.beginner = customerSnapshotBeginFunc(func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
			t.Fatal("invalid coordinates opened read transaction")
			return nil, nil
		})
		v, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), tc.tenant, tc.product, tc.release, tc.profile, tc.at)
		if !errors.Is(err, packageapp.ErrValidation) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
			t.Fatal("invalid snapshot input accepted", v, err)
		}
	}
	for _, store := range []*Store{nil, {}} {
		if _, err := NewCustomerPackageCreationSnapshotReader(store, customerAuditHasher{}, localed25519.PayloadVerifier{}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatal("unconfigured reader accepted", err)
		}
	}
	if _, err := NewCustomerPackageCreationSnapshotReader(s, nil, localed25519.PayloadVerifier{}); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("missing hasher accepted", err)
	}
	if _, err := NewCustomerPackageCreationSnapshotReader(s, customerAuditHasher{}, nil); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("missing verifier accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadCustomerPackageCreationSnapshot(ctx, "tenant", "product", "release", "profile", customerGovernanceNow); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context opened a snapshot", err)
	}
}

func TestCustomerPackageCreationSnapshotDoesNotAcquireWriterFence(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	r := newCustomerCreationSnapshotReader(t, s)
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT id FROM tenants WHERE id='tenant' FOR UPDATE; SELECT id FROM redaction_profiles WHERE id='profile' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	v, err := r.ReadCustomerPackageCreationSnapshot(ctx, "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil || v.Profile.ID != "profile" || v.Snapshot.ProductID != "product" {
		t.Fatal("snapshot blocked by writer fence", v, err)
	}
}

func TestCustomerPackageCreationSnapshotUsesCallerClockForEveryTimeSensitiveSection(t *testing.T) {
	s := customerCreationSnapshotFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE object_retention_policies SET status='verified',verification_expires_at=$1 WHERE id='retention'`, customerGovernanceNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := newCustomerCreationSnapshotReader(t, s)
	current, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil || len(current.Snapshot.Exceptions) != 1 || len(current.Snapshot.Waivers) != 2 || current.Snapshot.ObjectLockProofs[0]["status"] != "verified" {
		t.Fatal("current generation clock was not shared", current, err)
	}
	later, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow.Add(48*time.Hour))
	if err != nil || len(later.Snapshot.Exceptions) != 0 || len(later.Snapshot.Waivers) != 0 || later.Snapshot.ObjectLockProofs[0]["status"] != "stale" {
		t.Fatal("reader used wall clock or mixed generation times", later, err)
	}
}

func TestCustomerPackageCreationSnapshotInspectsAuditWithoutExportingPrivateDetails(t *testing.T) {
	s := customerAuditFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES('profile','tenant','Public',ARRAY['sbom'],'{}','profile.v1','2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	r := newCustomerCreationSnapshotReader(t, s)
	view, err := r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil {
		t.Fatal(err)
	}
	audit := view.Snapshot.VerificationMaterial["audit_chain"].(map[string]any)
	body, err := json.Marshal(view)
	if err != nil || audit["result"] != "passed" || audit["latest_sequence"] != int64(130) || strings.Contains(string(body), "private-") || strings.Contains(string(body), "sealed-key") {
		t.Fatal("audit result changed or private source escaped", audit, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE audit_chain_entries SET metadata='{"changed":true}' WHERE id='audit_001'`); err != nil {
		t.Fatal(err)
	}
	view, err = r.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "product", "release", "profile", customerGovernanceNow)
	if err != nil || view.Snapshot.VerificationMaterial["audit_chain"].(map[string]any)["result"] != "failed" {
		t.Fatal("reader upgraded failed audit integrity", view, err)
	}
}
