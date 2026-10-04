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
)

// This exercises one private component of the complete customer snapshot,
// not a production reader or HTTP binding. Every invocation uses native SQL.
func customerCatalogFixture(t *testing.T) *Store {
	t.Helper()
	s := isolatedRelationalTestStore(t)
	for _, sql := range []string{
		`INSERT INTO tenants(id,name) VALUES('tenant','Customer'),('foreign_tenant','Foreign')`,
		`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product'),('sibling','tenant','Sibling','sibling'),('foreign_product','foreign_tenant','Foreign','foreign')`,
		`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','Project'),('sibling_project','tenant','sibling','Sibling'),('foreign_project','foreign_tenant','foreign_product','Foreign')`,
		`INSERT INTO releases(id,tenant_id,product_id,version,state,created_at,frozen_at) VALUES('release','tenant','product','1','draft','2026-10-01T12:34:56.123456Z','2026-10-02T12:34:56.123456Z'),('other_release','tenant','product','2','draft',now(),NULL),('sibling_release','tenant','sibling','1','draft',now(),NULL),('foreign_release','foreign_tenant','foreign_product','1','draft',now(),NULL),('bad_parent','tenant','foreign_product','bad','draft',now(),NULL)`,
		`INSERT INTO organizations(id,tenant_id,name,slug,status,schema_version,created_at) VALUES('org','tenant','Organization','organization','active','org.v1',now()),('foreign_org','foreign_tenant','Foreign','foreign','active','org.v1',now())`,
		`INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest) VALUES('artifact_evidence','tenant','Evidence','application/json',7,'sha256:evidence'),('artifact_sbom','tenant','SBOM','application/json',8,'sha256:sbom'),('artifact_vex','tenant','VEX','application/json',9,'sha256:vex'),('artifact_build','tenant','Build','application/json',10,'sha256:build'),('artifact_wrong_digest','tenant','Wrong','application/json',11,'sha256:wrong'),('artifact_sibling','tenant','Sibling','application/json',12,'sha256:sibling'),('foreign_artifact','foreign_tenant','Foreign','application/json',13,'sha256:foreign')`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs,payload_ref,metadata)
		VALUES('ev_selected','tenant','product','project','release','document','private-title-marker','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[{"type":"artifact","id":"artifact_evidence"},{"type":"artifact","id":"foreign_artifact"}]','private-payload-marker','{"token":"private-token-marker"}'),
		('ev_other_release','tenant','product',NULL,'other_release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[]',NULL,NULL),
		('ev_product_only','tenant','product',NULL,NULL,'document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending',NULL,NULL,NULL),
		('ev_sibling','tenant','sibling',NULL,'release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[{"type":"artifact","id":"artifact_sibling"}]',NULL,NULL),
		('ev_wrong_project','tenant','product','sibling_project','release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[]',NULL,NULL),
		('ev_wrong_release','tenant','product',NULL,'sibling_release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[]',NULL,NULL),
		('ev_foreign','foreign_tenant','product',NULL,'release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[]',NULL,NULL)`,
		`INSERT INTO sboms(id,tenant_id,evidence_id,release_id,artifact_id,format,spec_version,component_count,components) VALUES('sbom','tenant','ev_selected','release','artifact_sbom','CycloneDX','1.6',0,'[]'),('sbom_bad_scope','tenant','ev_sibling','release','artifact_sibling','CycloneDX','1.6',0,'[]')`,
		`INSERT INTO vex_documents(id,tenant_id,evidence_id,release_id,artifact_id,format,author,statement_count,status_summary,schema_version) VALUES('vex','tenant','ev_selected','release','artifact_vex','OpenVEX','Author',0,'{}','vex.v1')`,
		`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,started_at,status,outputs,schema_version,environment_hash) VALUES('build','tenant','project','release','test','commit',now(),'passed','[{"artifact_id":"artifact_build","digest":"sha256:build"},{"artifact_id":"artifact_wrong_digest","digest":"sha256:not-the-artifact"},{"artifact_id":"foreign_artifact","digest":"sha256:foreign"}]','build.v1','private-environment-marker'),('bad_project_build','tenant','sibling_project','release','test','commit',now(),'passed','[{"artifact_id":"artifact_sibling","digest":"sha256:sibling"}]','build.v1','private-environment-marker')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func customerCatalogReadTx(t *testing.T, s *Store) pgx.Tx {
	t.Helper()
	tx, err := s.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) })
	return tx
}

func TestCustomerPackageCatalogSnapshotScopesAllAssociations(t *testing.T) {
	s := customerCatalogFixture(t)
	tx := customerCatalogReadTx(t, s)
	read := func(tenant, product, release string) (customerPackageCatalogSnapshot, error) {
		return readCustomerPackageCatalogTx(t.Context(), tx, tenant, product, release, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	}
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"foreign_tenant", "product", "release"}, {"tenant", "product", "sibling_release"}, {"tenant", "product", "bad_parent"}, {"tenant", "product", "missing"}} {
		v, err := read(scope[0], scope[1], scope[2])
		if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) {
			t.Fatalf("wrong scope=%v value=%#v err=%v", scope, v, err)
		}
	}
	v, err := read("tenant", "product", "release")
	if err != nil {
		t.Fatal(err)
	}
	if v.Tenant["id"] != "tenant" || v.Product["id"] != "product" || v.Release["id"] != "release" || v.Release["created_at"] != "2026-10-01T12:34:56Z" || v.Release["frozen_at"] != "2026-10-02T12:34:56Z" {
		t.Fatalf("scope metadata=%#v", v)
	}
	if _, exists := v.Release["approved_at"]; exists {
		t.Fatal("absent approval time was not omitted")
	}
	if !reflect.DeepEqual(v.Evidence, []packageapp.EvidenceReference{{ID: "ev_selected", Type: "document"}}) {
		t.Fatal("evidence crossed scope", v.Evidence)
	}
	var artifacts []string
	for _, row := range v.Artifacts {
		artifacts = append(artifacts, row["id"].(string))
	}
	if strings.Join(artifacts, ",") != "artifact_build,artifact_evidence,artifact_sbom,artifact_vex" {
		t.Fatal("artifact scope or digest binding changed", artifacts)
	}
	orgs := v.Organization["records"].([]map[string]any)
	if len(orgs) != 1 || orgs[0]["id"] != "org" || len(v.Organization["limitations"].([]string)) != 1 {
		t.Fatal("organization scope or ownership limitation changed", v.Organization)
	}
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"private-", "foreign_", "ev_sibling", "ev_wrong_project", "ev_wrong_release", "artifact_sibling", "artifact_wrong_digest"} {
		if strings.Contains(string(body), excluded) {
			t.Fatal("private or out-of-scope metadata transferred", excluded)
		}
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE artifacts SET size=4611686018427387907 WHERE id='artifact_evidence'`); err != nil {
		t.Fatal(err)
	}
	precise, err := readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || precise.Artifacts[1]["size"].(json.Number).String() != "4611686018427387907" {
		t.Fatalf("artifact size lost precision: %#v err=%v", precise.Artifacts, err)
	}
	product, err := read("tenant", "product", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(product.Evidence, []packageapp.EvidenceReference{{ID: "ev_other_release", Type: "document"}, {ID: "ev_product_only", Type: "document"}, {ID: "ev_selected", Type: "document"}}) || len(product.Release) != 0 || len(product.Artifacts) != 0 {
		t.Fatal("product-only compatibility or scope changed", product)
	}
	var writes int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&writes); err != nil || writes != 0 {
		t.Fatalf("read created effects=%d err=%v", writes, err)
	}
}

type customerMetadataWatchTx struct {
	pgx.Tx
	largest int
}

func (w *customerMetadataWatchTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := w.Tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return customerMetadataWatchRows{Rows: rows, watch: w}, nil
}

type customerMetadataWatchRows struct {
	pgx.Rows
	watch *customerMetadataWatchTx
}

func (r customerMetadataWatchRows) Scan(dest ...any) error {
	if err := r.Rows.Scan(dest...); err != nil {
		return err
	}
	for _, value := range dest {
		if raw, ok := value.(*[]byte); ok && len(*raw) > r.watch.largest {
			r.watch.largest = len(*raw)
		}
	}
	return nil
}

func TestCustomerPackageCatalogSnapshotFailsClosedBeforeOversizedTransfer(t *testing.T) {
	s := customerCatalogFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"tenant text", `UPDATE tenants SET name=repeat('x',8388609) WHERE id='tenant'`, `UPDATE tenants SET name='Customer' WHERE id='tenant'`},
		{"organization text", `UPDATE organizations SET name=repeat('x',8388609) WHERE id='org'`, `UPDATE organizations SET name='Organization' WHERE id='org'`},
		{"artifact text", `UPDATE artifacts SET name=repeat('x',8388609) WHERE id='artifact_evidence'`, `UPDATE artifacts SET name='Evidence' WHERE id='artifact_evidence'`},
		{"malformed refs", `UPDATE evidence_items SET subject_refs='{}' WHERE id='ev_selected'`, `UPDATE evidence_items SET subject_refs='[]' WHERE id='ev_selected'`},
		{"malformed output", `UPDATE build_runs SET outputs='[null]' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"scalar output", `UPDATE build_runs SET outputs='42' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"large refs", `UPDATE evidence_items SET subject_refs=jsonb_build_array(jsonb_build_object('type','artifact','id',repeat('x',8388609))) WHERE id='ev_selected'`, `UPDATE evidence_items SET subject_refs='[]' WHERE id='ev_selected'`},
		{"many refs", `UPDATE evidence_items SET subject_refs=(SELECT jsonb_agg(jsonb_build_object('type','artifact','id','artifact_evidence')) FROM generate_series(1,4097)) WHERE id='ev_selected'`, `UPDATE evidence_items SET subject_refs='[]' WHERE id='ev_selected'`},
		{"nonfinite timestamp", `UPDATE products SET created_at='infinity' WHERE id='product'`, `UPDATE products SET created_at=now() WHERE id='product'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), tc.change); err != nil {
				t.Fatal(err)
			}
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			v, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) {
				t.Fatalf("partial/invalid snapshot=%#v err=%v", v, err)
			}
			if tx.largest > 2048 {
				t.Fatalf("oversized metadata was transferred: %d bytes", tx.largest)
			}
			if _, err := s.pool.Exec(t.Context(), tc.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
	// All metadata sections share the same byte budget, not one limit each.
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: 1})
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) || tx.largest != 0 {
		t.Fatalf("budget snapshot=%#v transfer=%d err=%v", v, tx.largest, err)
	}
	baseline := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", baseline); err != nil {
		t.Fatal(err)
	}
	// Every individual section fits this budget, but their combined metadata
	// exceeds it by one byte. Resetting the limit per section must not pass.
	combined := packageapp.MaxCustomerPackageManifestBytes - baseline.remainingBytes - 1
	budget := &customerSnapshotBudget{remainingBytes: combined}
	v, err = readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", budget)
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) || budget.remainingBytes != combined {
		t.Fatalf("cumulative budget snapshot=%#v remaining=%d err=%v", v, budget.remainingBytes, err)
	}
}

func TestCustomerPackageCatalogSnapshotBoundsEvidenceRowsAndIdentifiers(t *testing.T) {
	s := customerCatalogFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		SELECT 'overflow_'||n,'tenant','product','release','document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending' FROM generate_series(1,4096)n`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) {
		t.Fatalf("row overflow snapshot=%#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM evidence_items WHERE id='overflow_4096'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Evidence) != packageapp.MaxSecurityReviewEvidenceIDs {
		t.Fatalf("exact evidence row limit rejected: count=%d err=%v", len(v.Evidence), err)
	}
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM evidence_items WHERE id LIKE 'overflow_%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET id=repeat('é',513) WHERE id='ev_product_only'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) {
		t.Fatalf("identifier overflow snapshot=%#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET id=$1 WHERE id=$2`, "\u2003invalid", strings.Repeat("é", 513)); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageCatalogSnapshot{}) {
		t.Fatalf("noncanonical identifier snapshot=%#v err=%v", v, err)
	}
}

func TestCustomerPackageCatalogSnapshotKeepsOneViewAndDoesNotWaitForWriterFence(t *testing.T) {
	s := customerCatalogFixture(t)
	readTx := customerCatalogReadTx(t, s)
	read := func() (customerPackageCatalogSnapshot, error) {
		return readCustomerPackageCatalogTx(t.Context(), readTx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	}
	before, err := read()
	if err != nil {
		t.Fatal(err)
	}
	write, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = write.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), write, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := write.Exec(t.Context(), `UPDATE tenants SET name='After' WHERE id='tenant'; UPDATE products SET name='After' WHERE id='product'; UPDATE releases SET version='after' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	// Snapshot components must not acquire this writer fence on their separate
	// read connection: durable idempotent creation may already own it.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	stillBefore, err := readCustomerPackageCatalogTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, stillBefore) {
		t.Fatalf("uncommitted/writer-fenced snapshot=%#v err=%v", stillBefore, err)
	}
	if err := write.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	stillBefore, err = read()
	if err != nil || !reflect.DeepEqual(before, stillBefore) {
		t.Fatalf("mixed committed view=%#v err=%v", stillBefore, err)
	}
	after, err := readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || after.Tenant["name"] != "After" || after.Product["name"] != "After" || after.Release["version"] != "after" {
		t.Fatalf("new committed view=%#v err=%v", after, err)
	}
}

func TestCustomerPackageCatalogSnapshotRejectsRawInputsAndCancellation(t *testing.T) {
	s := customerCatalogFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][3]string{{"", "product", ""}, {" tenant", "product", ""}, {"tenant", "product ", ""}, {"tenant", "product", " release"}, {"tenant", strings.Repeat("é", 513), ""}, {"tenant", "product", "bad\x00id"}, {"tenant", "product", "\xff"}} {
		if _, err := readCustomerPackageCatalogTx(t.Context(), tx, scope[0], scope[1], scope[2], &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatalf("raw scope=%q err=%v", scope, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readCustomerPackageCatalogTx(ctx, tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	//nolint:staticcheck // Deliberate adversarial coverage of nil-context rejection.
	if _, err := readCustomerPackageCatalogTx(nil, tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal(err)
	}
	if _, err := readCustomerPackageCatalogTx(t.Context(), nil, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal(err)
	}
}

func TestCustomerPackageCatalogSnapshotValidatesBuildAndDeploymentParents(t *testing.T) {
	s := customerCatalogFixture(t)
	for _, sql := range []string{
		`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,started_at,status,outputs,schema_version) VALUES('foreign_build','foreign_tenant','foreign_project','foreign_release','test','commit',now(),'passed','[]','build.v1'),('other_release_build','tenant','project','other_release','test','commit',now(),'passed','[]','build.v1')`,
		`INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at) VALUES('environment','tenant','product','Production','production','environment.v1',now()),('foreign_environment','foreign_tenant','foreign_product','Production','production','environment.v1',now())`,
		`INSERT INTO deployment_events(id,tenant_id,environment_id,release_id,status,started_at,schema_version,created_at) VALUES('deployment','tenant','environment','release','passed',now(),'deployment.v1',now()),('other_deployment','tenant','environment','other_release','passed',now(),'deployment.v1',now()),('foreign_deployment','foreign_tenant','foreign_environment','foreign_release','passed',now(),'deployment.v1',now())`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,deployment_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		SELECT v.id,'tenant','product',NULL,'release',v.build,v.deployment,'document','Private','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending'
		FROM (VALUES('bad_foreign_build','foreign_build'::text,NULL::text),('bad_missing_build','missing',NULL),('bad_release_build','other_release_build',NULL),('bad_foreign_deployment',NULL,'foreign_deployment'),('bad_missing_deployment',NULL,'missing'),('bad_release_deployment',NULL,'other_deployment'),('valid_parents','build','deployment'))v(id,build,deployment)`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	v, err := readCustomerPackageCatalogTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(v.Evidence, []packageapp.EvidenceReference{{ID: "ev_selected", Type: "document"}, {ID: "valid_parents", Type: "document"}}) {
		t.Fatalf("invalid cross-context parents admitted: evidence=%#v err=%v", v.Evidence, err)
	}
}
