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
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func customerVerificationFixture(t *testing.T) *Store {
	t.Helper()
	s := customerProvenanceFixture(t)
	for _, sql := range []string{
		`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs,created_at) VALUES
		 ('bundle','tenant','release','draft','{"token":"private-bundle-manifest-marker"}','sha256:bundle','[]','2026-10-01T12:34:56.123456Z'),
		 ('sibling_bundle','tenant','sibling_release','draft','{}','sha256:sibling','[]',now()),('foreign_bundle','foreign_tenant','foreign_release','draft','{}','sha256:foreign','[]',now())`,
		`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,payload_ref,verification_status,schema_version,created_at) VALUES
		 ('artifact_signature','tenant','artifact_evidence','sha256:evidence','cosign','private-signature-marker','private-payload-marker','not_verified','signature.v1',now()),
		 ('sibling_signature','tenant','artifact_sibling','sha256:sibling','cosign','private-signature-marker',NULL,'not_verified','signature.v1',now()),
		 ('foreign_signature','foreign_tenant','foreign_artifact','sha256:foreign','cosign','private-signature-marker',NULL,'not_verified','signature.v1',now())`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	checks := `[{"name":"z","result":"limited","detail":"recorded scope","x-private":"private-check-extension-marker"},{"name":"a","result":"failed"}]`
	profile := `{"id":"recorded-profile","version":"verification-profile.v1","required_checks":["z","a","z"],"trust_material":["sha256:root"],"identity_policy":"subject-bound","transparency_proof":"not checked","payload_scope":"stored subject","payload_digest":"sha256:subject","limitations":["recorded profile limitation"],"x-private":{"token":"private-profile-extension-marker"}}`
	for _, row := range [][4]string{
		{"verify_bundle", "tenant", "release_bundle", "bundle"}, {"verify_evidence", "tenant", "evidence_item", "ev_selected"},
		{"verify_signature", "tenant", "artifact_signature", "artifact_signature"}, {"verify_attestation", "tenant", "build_attestation", "attestation"},
		{"wrong_bundle", "tenant", "release_bundle", "foreign_bundle"}, {"wrong_evidence", "tenant", "evidence_item", "ev_foreign"},
		{"wrong_signature", "tenant", "artifact_signature", "foreign_signature"}, {"wrong_attestation", "tenant", "build_attestation", "attestation_foreign"},
		{"sibling_bundle_result", "tenant", "release_bundle", "sibling_bundle"}, {"sibling_signature_result", "tenant", "artifact_signature", "sibling_signature"},
		{"wrong_parent_result", "tenant", "evidence_item", "ev_wrong_project"}, {"wrong_attestation_source", "tenant", "build_attestation", "attestation_wrong_source"},
		{"wrong_receipt_tenant", "foreign_tenant", "evidence_item", "ev_selected"}, {"unsupported_result", "tenant", "audit_chain", "tenant"},
	} {
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,assurance_profile,limitations,schema_version,verified_at)
		 VALUES($1,$2,$3,$4,'limited',$5,$6,ARRAY['recorded result limitation'],'verification-result.v2','2026-10-01T12:34:56.123456Z')`, row[0], row[1], row[2], row[3], checks, profile); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range [][5]string{
		{"cosign", "tenant", "artifact_evidence", "artifact_signature", "sha256:evidence"},
		{"wrong_cosign_tenant", "foreign_tenant", "artifact_evidence", "artifact_signature", "sha256:evidence"},
		{"wrong_cosign_signature", "tenant", "artifact_evidence", "foreign_signature", "sha256:evidence"},
		{"wrong_cosign_digest", "tenant", "artifact_evidence", "artifact_signature", "sha256:wrong"},
		{"sibling_cosign", "tenant", "artifact_sibling", "sibling_signature", "sha256:sibling"},
	} {
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO cosign_verifications(id,tenant_id,artifact_id,artifact_signature_id,subject_digest,result,checks,assurance_profile,limitations,schema_version,certificate_identity,certificate_issuer,rekor_uuid,created_at)
		 VALUES($1,$2,$3,$4,$5,'failed',$6,$7,ARRAY['recorded cosign limitation'],'cosign.v1','private-certificate-marker','private-issuer-marker','private-provider-marker','2026-10-01T12:34:56.123456Z')`, row[0], row[1], row[2], row[3], row[4], checks, profile); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func customerVerificationResultIDs(v map[string]any) string {
	var ids []string
	for _, row := range v["verification_results"].([]map[string]any) {
		ids = append(ids, row["id"].(string))
	}
	return strings.Join(ids, ",")
}

func TestCustomerPackageVerificationMetadataSnapshotSelectsScopedRecordedPublicFields(t *testing.T) {
	s := customerVerificationFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	if customerVerificationResultIDs(v) != "verify_attestation,verify_bundle,verify_evidence,verify_signature" {
		t.Fatal("receipt subject ownership changed", v)
	}
	bundles, results, cosign := v["release_bundles"].([]map[string]any), v["verification_results"].([]map[string]any), v["cosign_assessments"].([]map[string]any)
	if len(bundles) != 1 || bundles[0]["id"] != "bundle" || bundles[0]["created_at"] != "2026-10-01T12:34:56Z" || !reflect.DeepEqual(bundles[0]["signature_refs"], []string(nil)) || len(cosign) != 1 || cosign[0]["id"] != "cosign" || cosign[0]["result"] != "failed" {
		t.Fatal("bundle/cosign shape or scope changed", v)
	}
	wantProfile := domain.VerificationProfile{ID: "recorded-profile", Version: "verification-profile.v1", RequiredChecks: []string{"z", "a", "z"}, TrustMaterial: []string{"sha256:root"}, IdentityPolicy: "subject-bound", TransparencyProof: "not checked", PayloadScope: "stored subject", PayloadDigest: "sha256:subject", Limitations: []string{"recorded profile limitation"}}
	wantChecks := []map[string]any{{"name": "a", "result": "failed", "detail": ""}, {"name": "z", "result": "limited", "detail": "recorded scope"}}
	for _, row := range append(results, cosign...) {
		if !reflect.DeepEqual(row["profile"], wantProfile) || !reflect.DeepEqual(row["checks"], wantChecks) {
			t.Fatal("recorded assurance metadata was normalized/upgraded", row)
		}
	}
	if results[0]["result"] != "limited" || results[0]["verified_at"] != "2026-10-01T12:34:56Z" || v["hash_algorithm"] != "sha256" || v["canonicalization"] != domain.CanonicalizationProfileVersion || v["manifest_hash_field"] != "manifest_hash" {
		t.Fatal("public constants/state/time changed", v)
	}
	body, err := json.Marshal(v)
	if err != nil || strings.Contains(string(body), "private-") || strings.Contains(string(body), "wrong_") || strings.Contains(string(body), "sibling") || tx.privateFound {
		t.Fatalf("private/unrelated metadata transferred: %s private=%v err=%v", body, tx.privateFound, err)
	}
	product, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(product["release_bundles"].([]map[string]any)) != 0 || len(product["verification_results"].([]map[string]any)) != 0 || len(product["cosign_assessments"].([]map[string]any)) != 0 {
		t.Fatalf("product-only release selection changed: %#v err=%v", product, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("read-only effects=%d err=%v", effects, err)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotRejectsMalformedBeforeTransfer(t *testing.T) {
	s := customerVerificationFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"checks object", `UPDATE verification_results SET checks='{}' WHERE id='verify_bundle'`, `UPDATE verification_results SET checks='[]' WHERE id='verify_bundle'`},
		{"private nested check", `UPDATE verification_results SET checks='[{"name":"a","detail":{"token":"private-nested-marker"}}]' WHERE id='verify_bundle'`, `UPDATE verification_results SET checks='[]' WHERE id='verify_bundle'`},
		{"null check", `UPDATE verification_results SET checks='[null]' WHERE id='verify_bundle'`, `UPDATE verification_results SET checks='[]' WHERE id='verify_bundle'`},
		{"check overflow", `UPDATE verification_results SET checks=(SELECT jsonb_agg(jsonb_build_object('name','a','result','passed')) FROM generate_series(1,4097)) WHERE id='verify_bundle'`, `UPDATE verification_results SET checks='[]' WHERE id='verify_bundle'`},
		{"check byte overflow", `UPDATE verification_results SET checks=jsonb_build_array(jsonb_build_object('name','a','detail',repeat('x',8388609))) WHERE id='verify_bundle'`, `UPDATE verification_results SET checks='[]' WHERE id='verify_bundle'`},
		{"profile array", `UPDATE verification_results SET assurance_profile='[]' WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"private nested profile", `UPDATE verification_results SET assurance_profile='{"id":{"token":"private-nested-marker"}}' WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"profile list object", `UPDATE verification_results SET assurance_profile='{"trust_material":[{"token":"private-nested-marker"}]}' WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"profile null list item", `UPDATE verification_results SET assurance_profile='{"required_checks":[null]}' WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"profile list overflow", `UPDATE verification_results SET assurance_profile=jsonb_build_object('required_checks',(SELECT jsonb_agg('a'::text) FROM generate_series(1,4097))) WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"profile byte overflow", `UPDATE verification_results SET assurance_profile=jsonb_build_object('id',repeat('x',8388609)) WHERE id='verify_bundle'`, `UPDATE verification_results SET assurance_profile='{}' WHERE id='verify_bundle'`},
		{"limitations dimensions", `UPDATE verification_results SET limitations=ARRAY[['a','b'],['c','d']] WHERE id='verify_bundle'`, `UPDATE verification_results SET limitations='{}' WHERE id='verify_bundle'`},
		{"limitations null", `UPDATE verification_results SET limitations=ARRAY[NULL::text] WHERE id='verify_bundle'`, `UPDATE verification_results SET limitations='{}' WHERE id='verify_bundle'`},
		{"limitations overflow", `UPDATE cosign_verifications SET limitations=ARRAY(SELECT 'a' FROM generate_series(1,4097)) WHERE id='cosign'`, `UPDATE cosign_verifications SET limitations='{}' WHERE id='cosign'`},
		{"bundle list type", `UPDATE release_bundles SET signature_refs='[{}]' WHERE id='bundle'`, `UPDATE release_bundles SET signature_refs='[]' WHERE id='bundle'`},
		{"out of range time", `UPDATE verification_results SET verified_at='10000-01-01T00:00:00Z' WHERE id='verify_bundle'`, `UPDATE verification_results SET verified_at=now() WHERE id='verify_bundle'`},
		{"infinite time", `UPDATE cosign_verifications SET created_at='infinity' WHERE id='cosign'`, `UPDATE cosign_verifications SET created_at=now() WHERE id='cosign'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", budget)
			if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.privateFound || tx.largest > 4096 {
				t.Fatalf("malformed metadata=%#v budget=%d private=%v transfer=%d err=%v", v, budget.remainingBytes, tx.privateFound, tx.largest, err)
			}
		})
	}
}

func TestCustomerPackageVerificationMetadataSnapshotFailsClosedForForeignParents(t *testing.T) {
	s := customerVerificationFixture(t)
	for _, tc := range []struct{ name, change, restore, absent string }{
		{"bundle parent", `UPDATE release_bundles SET release_id='sibling_release' WHERE id='bundle'`, `UPDATE release_bundles SET release_id='release' WHERE id='bundle'`, "verify_bundle"},
		{"evidence product", `UPDATE evidence_items SET product_id='sibling' WHERE id='ev_selected'`, `UPDATE evidence_items SET product_id='product' WHERE id='ev_selected'`, "verify_evidence,verify_signature,cosign"},
		{"evidence project", `UPDATE evidence_items SET project_id='sibling_project' WHERE id='ev_selected'`, `UPDATE evidence_items SET project_id='project' WHERE id='ev_selected'`, "verify_evidence,verify_signature,cosign"},
		{"attestation source tenant", `UPDATE build_attestations SET evidence_id='foreign_attestation_source' WHERE id='attestation'`, `UPDATE build_attestations SET evidence_id='attestation_source' WHERE id='attestation'`, "verify_attestation"},
		{"attestation source type", `UPDATE evidence_items SET type='document' WHERE id='attestation_source'`, `UPDATE evidence_items SET type='build_attestation' WHERE id='attestation_source'`, "verify_attestation"},
		{"attestation source payload", `UPDATE evidence_items SET payload_hash='sha256:changed' WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_hash='sha256:attestation' WHERE id='attestation_source'`, "verify_attestation"},
		{"build collector tenant", `UPDATE build_runs SET collector_id='foreign_collector' WHERE id='build'`, `UPDATE build_runs SET collector_id='collector' WHERE id='build'`, "verify_attestation"},
		{"signature artifact tenant", `UPDATE artifact_signatures SET artifact_id='foreign_artifact' WHERE id='artifact_signature'`, `UPDATE artifact_signatures SET artifact_id='artifact_evidence' WHERE id='artifact_signature'`, "verify_signature,cosign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(v)
			for _, id := range strings.Split(tc.absent, ",") {
				if strings.Contains(string(body), `"id":"`+id+`"`) {
					t.Fatal("incoherent parent retained", id, string(body))
				}
			}
		})
	}
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"foreign_tenant", "product", "release"}, {"tenant", "product", "sibling_release"}} {
		budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), scope[0], scope[1], scope[2], budget)
		if !errors.Is(err, packageapp.ErrNotFound) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
			t.Fatalf("foreign root=%v v=%#v err=%v", scope, v, err)
		}
	}
}

func TestCustomerPackageVerificationMetadataSnapshotUsesOneViewWithoutWriterLocks(t *testing.T) {
	s := customerVerificationFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE verification_results SET result='failed' WHERE id='verify_bundle'; UPDATE cosign_verifications SET result='limited' WHERE id='cosign'`); err != nil {
		t.Fatal(err)
	}
	again, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, again) {
		t.Fatalf("mixed snapshot=%#v err=%v", again, err)
	}
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`SELECT pg_advisory_xact_lock(hashtext('audit-chain/tenant'))`, `SELECT id FROM tenants WHERE id='tenant' FOR UPDATE`, `SELECT id FROM release_bundles WHERE id='bundle' FOR UPDATE`, `SELECT id FROM verification_results WHERE id='verify_bundle' FOR UPDATE`, `SELECT id FROM artifact_signatures WHERE id='artifact_signature' FOR UPDATE`, `SELECT id FROM cosign_verifications WHERE id='cosign' FOR UPDATE`} {
		if _, err := writer.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	newView, err := readCustomerPackageVerificationMetadataTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || newView["verification_results"].([]map[string]any)[1]["result"] != "failed" || newView["cosign_assessments"].([]map[string]any)[0]["result"] != "limited" {
		t.Fatalf("read blocked or missed committed receipts: %#v err=%v", newView, err)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotHonorsBoundsAndLegacyEmptyMetadata(t *testing.T) {
	s := customerVerificationFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE verification_results SET checks='null',assurance_profile='{}',limitations='{}'; UPDATE cosign_verifications SET checks='[]',assurance_profile='null',limitations='{}'`); err != nil {
		t.Fatal(err)
	}
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", budget)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range append(v["verification_results"].([]map[string]any), v["cosign_assessments"].([]map[string]any)...) {
		if checks := row["checks"].([]map[string]any); checks == nil || len(checks) != 0 {
			t.Fatal("legacy null checks changed", row)
		}
		if !reflect.DeepEqual(row["profile"], domain.VerificationProfile{}) || !reflect.DeepEqual(row["limitations"], []string(nil)) {
			t.Fatal("legacy empty profile/list changed", row)
		}
	}
	used := packageapp.MaxCustomerPackageManifestBytes - budget.remainingBytes
	exact := &customerSnapshotBudget{remainingBytes: used}
	if _, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", exact); err != nil || exact.remainingBytes != 0 {
		t.Fatalf("exact budget=%d err=%v", exact.remainingBytes, err)
	}
	for _, remaining := range []int{0, used - 1} {
		watch := &customerMetadataWatchTx{Tx: tx}
		b := &customerSnapshotBudget{remainingBytes: remaining}
		if v, err := readCustomerPackageVerificationMetadataTx(t.Context(), watch, "tenant", "product", "release", b); !errors.Is(err, packageapp.ErrConflict) || v != nil || b.remainingBytes != remaining {
			t.Fatalf("short budget accepted=%#v budget=%d err=%v", v, b.remainingBytes, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readCustomerPackageVerificationMetadataTx(ctx, tx, "tenant", "product", "release", budget); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("canceled snapshot", v, err)
	}
	for _, bad := range []string{" tenant", "tenant\x00", strings.Repeat("x", 1025)} {
		if v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, bad, "product", "release", budget); !errors.Is(err, packageapp.ErrValidation) || v != nil {
			t.Fatal("noncanonical tenant", v, err)
		}
	}
}

func TestCustomerPackageVerificationMetadataSnapshotKeepsOnlyOwnedBundleSignatureReferences(t *testing.T) {
	s := customerVerificationFixture(t)
	for _, sql := range []string{
		`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,valid_from) VALUES('key','tenant','key','Ed25519','active','public',decode('707269766174652d6b6579','hex'),now()),('foreign_key','foreign_tenant','foreign','Ed25519','active','public',NULL,now())`,
		`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value) VALUES('bundle_signature','tenant','release_bundle','bundle','key','Ed25519','private-signature-marker'),('other_signature','tenant','release_bundle','sibling_bundle','key','Ed25519','private-signature-marker'),('foreign_bundle_signature','foreign_tenant','release_bundle','bundle','foreign_key','Ed25519','private-signature-marker')`,
		`UPDATE release_bundles SET signature_refs='["bundle_signature","bundle_signature"]' WHERE id='bundle'`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(v["release_bundles"].([]map[string]any)[0]["signature_refs"], []string{"bundle_signature", "bundle_signature"}) || tx.privateFound {
		t.Fatalf("owned public references changed: %#v err=%v", v, err)
	}
	for _, ref := range []string{"other_signature", "foreign_bundle_signature", "missing_signature"} {
		t.Run(ref, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), `UPDATE release_bundles SET signature_refs=jsonb_build_array('bundle_signature',$1::text) WHERE id='bundle'`, ref); err != nil {
				t.Fatal(err)
			}
			v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v["release_bundles"].([]map[string]any)) != 0 {
				t.Fatalf("incoherent bundle was exported or silently trimmed: %#v err=%v", v, err)
			}
		})
	}
}

func TestCustomerPackageVerificationMetadataSnapshotEnforcesReceiptRowCapacity(t *testing.T) {
	s := customerVerificationFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,assurance_profile,limitations,schema_version,verified_at)
	 SELECT 'capacity_'||lpad(n::text,4,'0'),'tenant','evidence_item','ev_selected','not_verified','[]','{}','{}','verification-result.v2',now() FROM generate_series(1,4092)n`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v["verification_results"].([]map[string]any)) != 4096 {
		t.Fatalf("exact row capacity rejected: count=%#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at) VALUES('capacity_overflow','tenant','evidence_item','ev_selected','not_verified','[]',now())`); err != nil {
		t.Fatal(err)
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", budget); !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.largest > 4096 {
		t.Fatalf("receipt overflow truncated/transferred: %#v budget=%d transfer=%d err=%v", v, budget.remainingBytes, tx.largest, err)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotBoundsAttestationSubjectInventory(t *testing.T) {
	s := customerVerificationFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version,created_at)
	 SELECT 'capacity_attestation_'||lpad(n::text,4,'0'),'tenant','build','attestation_source','private-payload-marker','sha256:attestation',7,'application/json','predicate','[]',0,0,'accepted','attestation.v1',now() FROM generate_series(1,4095)n`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || customerVerificationResultIDs(v) != "verify_attestation,verify_bundle,verify_evidence,verify_signature" {
		t.Fatalf("exact subject capacity rejected: %#v err=%v", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version,created_at)
	 VALUES('capacity_attestation_overflow','tenant','build','attestation_source','private-payload-marker','sha256:attestation',7,'application/json','predicate','[]',0,0,'accepted','attestation.v1',now())`); err != nil {
		t.Fatal(err)
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if v, err := readCustomerPackageVerificationMetadataTx(t.Context(), tx, "tenant", "product", "release", budget); !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.largest != 0 {
		t.Fatalf("subject inventory was unbounded/truncated: %#v budget=%d transfer=%d err=%v", v, budget.remainingBytes, tx.largest, err)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotAcceptsExactPublicListCapacity(t *testing.T) {
	s := customerVerificationFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE verification_results SET checks=(SELECT jsonb_agg(jsonb_build_object('name','a','result','limited')) FROM generate_series(1,4096)),assurance_profile=jsonb_build_object('required_checks',(SELECT jsonb_agg('a'::text) FROM generate_series(1,4096))),limitations=ARRAY(SELECT 'recorded' FROM generate_series(1,4096)) WHERE id='verify_bundle'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	row := v["verification_results"].([]map[string]any)[1]
	if len(row["checks"].([]map[string]any)) != 4096 || len(row["profile"].(domain.VerificationProfile).RequiredChecks) != 4096 || len(row["limitations"].([]string)) != 4096 || row["result"] != "limited" {
		t.Fatal("public arrays silently truncated or result upgraded", row)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotPreservesProductOnlyOwnershipAndRecordedFailure(t *testing.T) {
	s := customerVerificationFixture(t)
	for _, sql := range []string{
		`INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at) VALUES('unreleased_result','tenant','evidence_item','ev_product_only','failed','[]',now()),('other_release_result','tenant','evidence_item','ev_other_release','passed','[]',now())`,
		`UPDATE artifact_signatures SET subject_digest='sha256:does-not-match-artifact' WHERE id='artifact_signature'`,
		`UPDATE cosign_verifications SET subject_digest='sha256:does-not-match-artifact' WHERE id='cosign'`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || customerVerificationResultIDs(v) != "unreleased_result" || v["verification_results"].([]map[string]any)[0]["result"] != "failed" {
		t.Fatalf("product-only receipt scope changed: %#v err=%v", v, err)
	}
	v, err = readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || customerVerificationResultIDs(v) != "verify_attestation,verify_bundle,verify_evidence,verify_signature" || len(v["cosign_assessments"].([]map[string]any)) != 1 || v["cosign_assessments"].([]map[string]any)[0]["result"] != "failed" {
		t.Fatalf("recorded failed signature was hidden or upgraded: %#v err=%v", v, err)
	}
}

func TestCustomerPackageVerificationMetadataSnapshotChecksOptionalCosignImageParents(t *testing.T) {
	s := customerVerificationFixture(t)
	for _, sql := range []string{
		`INSERT INTO container_images(id,tenant_id,artifact_id,repository,digest,schema_version,created_at) VALUES('image','tenant','artifact_evidence','public-image','sha256:evidence','image.v1',now()),('foreign_image','foreign_tenant','foreign_artifact','foreign-image','sha256:foreign','image.v1',now()),('sibling_image','tenant','artifact_sibling','sibling-image','sha256:sibling','image.v1',now())`,
		`UPDATE cosign_verifications SET container_image_id='image' WHERE id='cosign'`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v["cosign_assessments"].([]map[string]any)) != 1 {
		t.Fatalf("owned optional image lost: %#v err=%v", v, err)
	}
	for _, id := range []string{"foreign_image", "sibling_image", "missing_image"} {
		t.Run(id, func(t *testing.T) {
			if _, err := s.pool.Exec(t.Context(), `UPDATE cosign_verifications SET container_image_id=$1 WHERE id='cosign'`, id); err != nil {
				t.Fatal(err)
			}
			v, err := readCustomerPackageVerificationMetadataTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v["cosign_assessments"].([]map[string]any)) != 0 || customerVerificationResultIDs(v) != "verify_attestation,verify_bundle,verify_evidence,verify_signature" {
				t.Fatalf("incoherent image retained or unrelated receipts lost: %#v err=%v", v, err)
			}
		})
	}
}
