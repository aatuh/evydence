package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func customerEvidenceFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	for _, scope := range [][4]string{{"selected", "tenant", "product", "release"}, {"unreleased", "tenant", "product", ""}, {"sibling", "tenant", "sibling", "sibling_release"}, {"sibling_unreleased", "tenant", "sibling", ""}, {"foreign", "foreign_tenant", "foreign_product", "foreign_release"}} {
		for _, kind := range []string{"sbom", "vulnerability_scan", "vex", "openapi_contract"} {
			if _, err := s.pool.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs,payload_ref,metadata)
			 VALUES($1,$2,$3,$4,$5,'private-title-marker','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','[]','private-payload-marker','{"token":"private-token-marker"}')`, "source_"+scope[0]+"_"+kind, scope[1], scope[2], nullableString(scope[3]), kind); err != nil {
				t.Fatal(err)
			}
		}
		queries := []struct {
			sql, kind string
		}{
			{`INSERT INTO sboms(id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES($1,$2,$3,$4,'CycloneDX','1.6',1,'[{"name":"private-component-marker","token":"private-token-marker"}]')`, "sbom"},
			{`INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings) VALUES($1,$2,$3,$4,'scanner','image','{"high":2}','[{"vulnerability":"private-finding-marker"}]')`, "vulnerability_scan"},
			{`INSERT INTO vex_documents(id,tenant_id,evidence_id,release_id,format,author,version,statement_count,status_summary,schema_version) VALUES($1,$2,$3,$4,'OpenVEX','private-author-marker','1',1,'{"not_affected":1}','vex.v1')`, "vex"},
			{`INSERT INTO openapi_contracts(id,tenant_id,evidence_id,release_id,product_id,version,hash,path_count,operations) VALUES($1,$2,$3,$4,$5,'1','sha256:contract',2,'[{"path":" /z ","method":" post ","operation_id":"create","required_request_fields":["id"],"response_statuses":["201"],"x-private":{"token":"private-extension-marker"}},{"path":"/a","method":"GET","deprecated":true},{"path":" ","method":"GET"}]')`, "openapi_contract"},
		}
		for _, q := range queries {
			args := []any{q.kind + "_" + scope[0], scope[1], "source_" + scope[0] + "_" + q.kind, nullableString(scope[3])}
			if q.kind == "openapi_contract" {
				args = append(args, scope[2])
			}
			if _, err := s.pool.Exec(t.Context(), q.sql, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, sql := range []string{
		`INSERT INTO contract_diffs(id,tenant_id,base_contract_id,target_contract_id,product_id,release_id,result,document,schema_version,created_at)
		 VALUES('diff_selected','tenant','openapi_contract_unreleased','openapi_contract_selected','product','release','breaking','{"id":"private-document-id-marker","token":"private-token-marker","breaking_changes":["removed operation"],"non_breaking_changes":["added operation"]}','contract-diff.v1',now()),('diff_cross_product','tenant','openapi_contract_sibling','openapi_contract_selected','product','release','breaking','{}','contract-diff.v1',now()),('diff_foreign','tenant','openapi_contract_foreign','openapi_contract_selected','product','release','breaking','{}','contract-diff.v1',now())`,
		`INSERT INTO sboms(id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES('sbom_cross_source','tenant','source_foreign_sbom','release','CycloneDX','1.6',0,'[]'),('sbom_release_mismatch','tenant','source_unreleased_sbom','release','CycloneDX','1.6',0,'[]')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestCustomerPackageEvidenceSnapshotSelectsOnlyPublicScopedFields(t *testing.T) {
	s := customerEvidenceFixture(t)
	watch := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageEvidenceTx(t.Context(), watch, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.SBOMs) != 1 || v.SBOMs[0]["id"] != "sbom_selected" || len(v.Scans) != 1 || v.Scans[0]["id"] != "vulnerability_scan_selected" || len(v.VEX) != 1 || v.VEX[0]["id"] != "vex_selected" {
		t.Fatalf("parsed metadata scope=%#v err=%v", v, err)
	}
	if !reflect.DeepEqual(v.Scans[0]["summary"], map[string]int{"high": 2}) || !reflect.DeepEqual(v.VEX[0]["status_summary"], map[string]int{"not_affected": 1}) || v.Scans[0]["finding_count"].(json.Number).String() != "1" {
		t.Fatal("count projection changed", v)
	}
	contracts := v.Contracts["openapi_contracts"].([]map[string]any)
	diffs := v.Contracts["contract_diffs"].([]map[string]any)
	if len(contracts) != 1 || contracts[0]["id"] != "openapi_contract_selected" || len(diffs) != 1 || diffs[0]["id"] != "diff_selected" || !reflect.DeepEqual(diffs[0]["breaking_changes"], []string{"removed operation"}) {
		t.Fatal("contract scope or relational identity changed", v.Contracts)
	}
	ops := contracts[0]["operations"].([]map[string]any)
	if len(ops) != 2 || ops[0]["label"] != "GET /a" || ops[1]["label"] != "POST /z" || contracts[0]["operation_count"].(json.Number).String() != "3" || len(v.Contracts["limitations"].([]string)) != 3 {
		t.Fatal("contract summary compatibility changed", contracts)
	}
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-", "foreign", "sibling", "cross_source", "release_mismatch", "sbom_bad_scope"} {
		if strings.Contains(string(body), private) {
			t.Fatal("nonpublic/out-of-scope data transferred", private)
		}
	}
	if watch.privateFound {
		t.Fatal("nonpublic source fields crossed the database driver")
	}
	product, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(product.SBOMs) != 1 || product.SBOMs[0]["id"] != "sbom_unreleased" || len(product.Scans) != 1 || product.Scans[0]["id"] != "vulnerability_scan_unreleased" || len(product.VEX) != 1 || product.VEX[0]["id"] != "vex_unreleased" {
		t.Fatalf("product-only documents crossed product or release: %#v err=%v", product, err)
	}
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"tenant", "product", "sibling_release"}, {"foreign_tenant", "product", "release"}} {
		value, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), scope[0], scope[1], scope[2], &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(value, customerPackageEvidenceSnapshot{}) {
			t.Fatalf("foreign root snapshot=%#v err=%v", value, err)
		}
	}
}

func TestCustomerPackageEvidenceSnapshotRejectsMalformedAndOversizedPublicData(t *testing.T) {
	s := customerEvidenceFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"count type", `UPDATE vulnerability_scans SET summary='{"high":"private-marker"}' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET summary='{"high":2}' WHERE id='vulnerability_scan_selected'`},
		{"negative count", `UPDATE vex_documents SET statement_count=-1 WHERE id='vex_selected'`, `UPDATE vex_documents SET statement_count=1 WHERE id='vex_selected'`},
		{"fractional count", `UPDATE vex_documents SET status_summary='{"not_affected":1.5}' WHERE id='vex_selected'`, `UPDATE vex_documents SET status_summary='{"not_affected":1}' WHERE id='vex_selected'`},
		{"count map limit", `UPDATE vulnerability_scans SET summary=(SELECT jsonb_object_agg('severity_'||n,1) FROM generate_series(1,4097)n) WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET summary='{}' WHERE id='vulnerability_scan_selected'`},
		{"malformed findings", `UPDATE vulnerability_scans SET findings='{}' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET findings='[]' WHERE id='vulnerability_scan_selected'`},
		{"operation shape", `UPDATE openapi_contracts SET operations='{}' WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET operations='[]' WHERE id='openapi_contract_selected'`},
		{"operation type", `UPDATE openapi_contracts SET operations='[{"path":"/a","method":42}]' WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET operations='[]' WHERE id='openapi_contract_selected'`},
		{"private object in list", `UPDATE openapi_contracts SET operations='[{"path":"/a","method":"GET","required_request_fields":[{"token":"private-nested-marker"}]}]' WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET operations='[]' WHERE id='openapi_contract_selected'`},
		{"private object in changes", `UPDATE contract_diffs SET document='{"breaking_changes":[{"token":"private-nested-marker"}]}' WHERE id='diff_selected'`, `UPDATE contract_diffs SET document='{}' WHERE id='diff_selected'`},
		{"oversized operation", `UPDATE openapi_contracts SET operations=jsonb_build_array(jsonb_build_object('path',repeat('x',8388609),'method','GET')) WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET operations='[]' WHERE id='openapi_contract_selected'`},
		{"operation array limit", `UPDATE openapi_contracts SET operations=(SELECT jsonb_agg(jsonb_build_object('path','/a','method','GET')) FROM generate_series(1,4097)) WHERE id='openapi_contract_selected'`, `UPDATE openapi_contracts SET operations='[]' WHERE id='openapi_contract_selected'`},
		{"null change", `UPDATE contract_diffs SET document='{"breaking_changes":[null]}' WHERE id='diff_selected'`, `UPDATE contract_diffs SET document='{}' WHERE id='diff_selected'`},
		{"large public text", `UPDATE sboms SET spec_version=repeat('x',8388609) WHERE id='sbom_selected'`, `UPDATE sboms SET spec_version='1.6' WHERE id='sbom_selected'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), tc.sql); err != nil {
				t.Fatal(err)
			}
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageEvidenceTx(t.Context(), tx, "tenant", "product", "release", budget)
			if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageEvidenceSnapshot{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatalf("invalid public snapshot=%#v budget=%d err=%v", v, budget.remainingBytes, err)
			}
			if tx.largest > 2048 {
				t.Fatal("oversized public JSON transferred", tx.largest)
			}
			if tx.privateFound {
				t.Fatal("malformed public fields transferred private objects")
			}
			if _, err := s.pool.Exec(t.Context(), tc.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCustomerPackageEvidenceSnapshotPreservesLegacyNullCollections(t *testing.T) {
	s := customerEvidenceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_scans SET summary='null',findings='null' WHERE id='vulnerability_scan_selected'; UPDATE vex_documents SET status_summary='null' WHERE id='vex_selected'; UPDATE openapi_contracts SET operations='null' WHERE id='openapi_contract_selected'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(v.Scans[0]["summary"], map[string]int{}) || !reflect.DeepEqual(v.VEX[0]["status_summary"], map[string]int{}) || v.Scans[0]["finding_count"].(json.Number).String() != "0" {
		t.Fatalf("legacy null counts changed: %#v err=%v", v, err)
	}
	contract := v.Contracts["openapi_contracts"].([]map[string]any)[0]
	if operations := contract["operations"].([]map[string]any); operations == nil || len(operations) != 0 || contract["operation_count"].(json.Number).String() != "0" {
		t.Fatal("legacy null operations changed", contract)
	}
}

func TestCustomerPackageEvidenceSnapshotSharesCatalogViewAndBudget(t *testing.T) {
	s := customerEvidenceFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageEvidenceTx(t.Context(), tx, "tenant", "product", "release", budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE sboms SET spec_version='after' WHERE id='sbom_selected'; UPDATE vulnerability_scans SET summary='{"high":4}' WHERE id='vulnerability_scan_selected'; UPDATE openapi_contracts SET version='after' WHERE id='openapi_contract_selected'`); err != nil {
		t.Fatal(err)
	}
	stillBefore, err := readCustomerPackageEvidenceTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, stillBefore) {
		t.Fatalf("mixed parsed view=%#v err=%v", stillBefore, err)
	}
	after, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || after.SBOMs[0]["spec_version"] != "after" || after.Scans[0]["summary"].(map[string]int)["high"] != 4 || after.Contracts["openapi_contracts"].([]map[string]any)[0]["version"] != "after" {
		t.Fatalf("new parsed view=%#v err=%v", after, err)
	}
	if _, err := readCustomerPackageEvidenceTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: 1}); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("tiny budget accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readCustomerPackageEvidenceTx(ctx, tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCustomerPackageEvidenceSnapshotPreservesContractOwnedLegacyScope(t *testing.T) {
	s := customerEvidenceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET product_id=NULL,release_id=NULL WHERE id='source_selected_openapi_contract'`); err != nil {
		t.Fatal(err)
	}
	// The existing native point reader permits product/release ownership from
	// the contract when optional source coordinates are absent. Preserve that
	// valid record while rechecking every parent that the source does declare.
	point, err := s.GetOpenAPIContractPoint(t.Context(), "tenant", "openapi_contract_selected")
	if err != nil || point.Contract.ProductID != "product" || point.Contract.ReleaseID != "release" {
		t.Fatalf("legacy characterization failed: point=%#v err=%v", point, err)
	}
	v, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Contracts["openapi_contracts"].([]map[string]any)) != 1 {
		t.Fatalf("valid contract-owned source lost: snapshot=%#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET product_id='sibling' WHERE id='source_selected_openapi_contract'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Contracts["openapi_contracts"].([]map[string]any)) != 0 {
		t.Fatalf("foreign declared source accepted: snapshot=%#v err=%v", v, err)
	}
}

func TestCustomerPackageEvidenceSnapshotRequiresUnambiguousArtifactBinding(t *testing.T) {
	s := customerEvidenceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE sboms SET artifact_id='artifact_evidence' WHERE id='sbom_selected'; UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact_evidence"}]' WHERE id='source_selected_sbom'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.SBOMs) != 1 || v.SBOMs[0]["artifact_id"] != "artifact_evidence" {
		t.Fatalf("matching artifact binding lost: %#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact_evidence"},{"type":"artifact","id":"foreign_artifact"}]' WHERE id='source_selected_sbom'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageEvidenceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.SBOMs) != 0 {
		t.Fatalf("ambiguous artifact binding accepted: %#v err=%v", v, err)
	}
}
