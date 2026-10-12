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
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func customerProvenanceProfile() packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"build", "build_attestation"}}
}

func customerProvenanceFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	for _, sql := range []string{
		`INSERT INTO collectors(id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version,created_at) VALUES('collector','tenant','Build CI','generic_ci','1','private-api-key-marker','active','[]','collector.v1','2026-10-01T00:00:00Z'),('foreign_collector','foreign_tenant','Foreign CI','generic_ci','1','private-api-key-marker','active','[]','collector.v1','2026-10-01T00:00:00Z')`,
		`UPDATE build_runs SET collector_id='collector' WHERE id='build'`,
		`UPDATE build_runs SET environment_hash='sha256:environment',parameters_hash='sha256:parameters',outputs='[{"artifact_id":"artifact_build","digest":"sha256:build","private":"private-output-extension-marker"},{"digest":"sha256:unregistered"}]',started_at='2026-10-01T12:34:56.123456Z',created_at='2026-10-01T12:34:56.123456Z',source_identity='{"token":"private-source-identity-marker"}',actor='private-actor-marker',job_id='private-job-marker',oidc_subject='private-oidc-marker' WHERE id='build'`,
		`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,started_at,status,outputs,schema_version,created_at) VALUES('sibling_build','tenant','sibling_project','sibling_release','test','commit','2026-10-01T00:00:00Z','passed','[]','build.v1','2026-10-01T00:00:00Z'),('foreign_build','foreign_tenant','foreign_project','foreign_release','test','commit','2026-10-01T00:00:00Z','passed','[]','build.v1','2026-10-01T00:00:00Z'),('unreleased_build','tenant','project','','test','commit','2026-10-01T00:00:00Z','passed','[]','build.v1','2026-10-01T00:00:00Z'),('unreleased_sibling','tenant','sibling_project','','test','commit','2026-10-01T00:00:00Z','passed','[]','build.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,type,title,source_system,observed_at,schema_version,payload_hash,payload_size,canonical_hash,canonicalization,trust_level,verification_status,payload_ref,metadata) VALUES
		 ('attestation_source','tenant','product','project','release','build','build_attestation','private-title-marker','test','2026-10-01T00:00:00Z','evidence.v1','sha256:attestation',7,'sha256:attestation','json','L2','pending','private-payload-marker','{"token":"private-token-marker"}'),
		 ('foreign_attestation_source','foreign_tenant','foreign_product','foreign_project','foreign_release','foreign_build','build_attestation','private-title-marker','test','2026-10-01T00:00:00Z','evidence.v1','sha256:attestation',7,'sha256:attestation','json','L2','pending','private-payload-marker','{}')`,
		`INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,builder_id,build_type,materials_count,signature_count,verification_status,schema_version,created_at) VALUES
		 ('attestation','tenant','build','attestation_source','private-payload-marker','sha256:attestation',7,'application/vnd.in-toto+json','https://slsa.dev/provenance/v1','["sha256:build"]','private-builder-marker','private-build-type-marker',3,2,'structurally_valid','attestation.v1','2026-10-01T12:34:56.123456Z'),
		 ('attestation_foreign','foreign_tenant','foreign_build','foreign_attestation_source','private-payload-marker','sha256:attestation',7,'application/vnd.in-toto+json','https://slsa.dev/provenance/v1','[]','private-builder-marker','private-build-type-marker',0,0,'accepted','attestation.v1','2026-10-01T00:00:00Z'),
		 ('attestation_wrong_source','tenant','build','foreign_attestation_source','private-payload-marker','sha256:attestation',7,'application/vnd.in-toto+json','https://slsa.dev/provenance/v1','[]','private-builder-marker','private-build-type-marker',0,0,'accepted','attestation.v1','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestCustomerPackageProvenanceSnapshotSelectsPublicScopedFields(t *testing.T) {
	s := customerProvenanceFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	builds, attestations := v["builds"].([]map[string]any), v["build_attestations"].([]map[string]any)
	if len(builds) != 1 || builds[0]["id"] != "build" || len(attestations) != 1 || attestations[0]["id"] != "attestation" {
		t.Fatal("provenance scope changed", v)
	}
	if builds[0]["started_at"] != "2026-10-01T12:34:56Z" || builds[0]["finished_at"] != "" || builds[0]["collector_id"] != "collector" || builds[0]["environment_hash"] != "sha256:environment" || builds[0]["run_attempt"].(json.Number).String() != "0" || attestations[0]["created_at"] != "2026-10-01T12:34:56Z" || attestations[0]["verification_status"] != "structurally_valid" || attestations[0]["payload_size"].(json.Number).String() != "7" {
		t.Fatal("public scalar/time/default/status changed", v)
	}
	if !reflect.DeepEqual(builds[0]["outputs"], []map[string]any{{"artifact_id": "", "digest": "sha256:unregistered"}, {"artifact_id": "artifact_build", "digest": "sha256:build"}}) || !reflect.DeepEqual(attestations[0]["subject_digests"], []string{"sha256:build"}) {
		t.Fatal("public output/digest list shape changed", v)
	}
	body, err := json.Marshal(v)
	if err != nil || strings.Contains(string(body), "private-") || tx.privateFound {
		t.Fatalf("private source fields crossed driver: body=%s private=%v err=%v", body, tx.privateFound, err)
	}
	product, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(product["builds"].([]map[string]any)) != 1 || product["builds"].([]map[string]any)[0]["id"] != "unreleased_build" || len(product["build_attestations"].([]map[string]any)) != 0 {
		t.Fatalf("product-only provenance scope=%#v err=%v", product, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("read effects=%d err=%v", effects, err)
	}
}

func TestCustomerPackageProvenanceSnapshotHonorsTypeSelection(t *testing.T) {
	s := customerProvenanceFixture(t)
	for _, tc := range []struct {
		types                []string
		builds, attestations int
	}{{nil, 0, 0}, {[]string{"build_attestation"}, 0, 0}, {[]string{"build"}, 1, 0}, {[]string{" build ", "build_attestation"}, 1, 1}} {
		profile := customerProvenanceProfile()
		profile.AllowedTypes = tc.types
		v, err := readCustomerPackageProvenanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", profile, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if err != nil || len(v["builds"].([]map[string]any)) != tc.builds || len(v["build_attestations"].([]map[string]any)) != tc.attestations {
			t.Fatalf("profile=%v provenance=%#v err=%v", tc.types, v, err)
		}
	}
}

func TestCustomerPackageProvenanceSnapshotRejectsMalformedBeforeTransfer(t *testing.T) {
	s := customerProvenanceFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"output shape", `UPDATE build_runs SET outputs='{}' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"nested private digest", `UPDATE build_runs SET outputs='[{"artifact_id":"artifact_build","digest":{"token":"private-nested-marker"}}]' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"output limit", `UPDATE build_runs SET outputs=(SELECT jsonb_agg(jsonb_build_object('digest','sha256:unregistered')) FROM generate_series(1,4097)) WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"large output", `UPDATE build_runs SET outputs=jsonb_build_array(jsonb_build_object('digest',repeat('x',8388609))) WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`},
		{"large public field", `UPDATE build_runs SET repository=repeat('x',8388609) WHERE id='build'`, `UPDATE build_runs SET repository=NULL WHERE id='build'`},
		{"subject shape", `UPDATE build_attestations SET subject_digests='{}' WHERE id='attestation'`, `UPDATE build_attestations SET subject_digests='[]' WHERE id='attestation'`},
		{"nested subject", `UPDATE build_attestations SET subject_digests='[{"token":"private-nested-marker"}]' WHERE id='attestation'`, `UPDATE build_attestations SET subject_digests='[]' WHERE id='attestation'`},
		{"subject limit", `UPDATE build_attestations SET subject_digests=(SELECT jsonb_agg('sha256:build'::text) FROM generate_series(1,4097)) WHERE id='attestation'`, `UPDATE build_attestations SET subject_digests='[]' WHERE id='attestation'`},
		{"negative count", `UPDATE build_attestations SET signature_count=-1 WHERE id='attestation'`, `UPDATE build_attestations SET signature_count=2 WHERE id='attestation'`},
		{"infinite time", `UPDATE build_runs SET finished_at='infinity' WHERE id='build'`, `UPDATE build_runs SET finished_at=NULL WHERE id='build'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), budget)
			if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.privateFound || tx.largest > 4096 {
				t.Fatalf("invalid metadata result=%#v budget=%d private=%v transfer=%d err=%v", v, budget.remainingBytes, tx.privateFound, tx.largest, err)
			}
		})
	}
}

func TestCustomerPackageProvenanceSnapshotKeepsOneViewAndBudget(t *testing.T) {
	s := customerProvenanceFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE build_runs SET status='failed' WHERE id='build'; UPDATE build_attestations SET verification_status='failed' WHERE id='attestation'`); err != nil {
		t.Fatal(err)
	}
	stillBefore, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, stillBefore) {
		t.Fatal("mixed provenance view", stillBefore, err)
	}
	newTx := customerCatalogReadTx(t, s)
	fresh := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	after, err := readCustomerPackageProvenanceTx(t.Context(), newTx, "tenant", "product", "release", customerProvenanceProfile(), fresh)
	if err != nil || after["builds"].([]map[string]any)[0]["status"] != "failed" || after["build_attestations"].([]map[string]any)[0]["verification_status"] != "failed" {
		t.Fatal("fresh provenance view", after, err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - fresh.remainingBytes
	for _, remaining := range []int{1, used - 1} {
		budget := &customerSnapshotBudget{remainingBytes: remaining}
		v, err := readCustomerPackageProvenanceTx(t.Context(), newTx, "tenant", "product", "release", customerProvenanceProfile(), budget)
		if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != remaining {
			t.Fatalf("partial/over-budget projection=%#v remaining=%d err=%v", v, budget.remainingBytes, err)
		}
	}
}

func TestCustomerPackageProvenanceSnapshotRejectsForeignRootsAndBadInputs(t *testing.T) {
	s := customerProvenanceFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"tenant", "product", "sibling_release"}, {"foreign_tenant", "product", "release"}} {
		profile := customerProvenanceProfile()
		profile.TenantID = scope[0]
		v, err := readCustomerPackageProvenanceTx(t.Context(), tx, scope[0], scope[1], scope[2], profile, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if !errors.Is(err, packageapp.ErrNotFound) || v != nil {
			t.Fatalf("foreign root result=%#v err=%v", v, err)
		}
	}
	for _, id := range []string{" product", "\u2003product", strings.Repeat("é", 513), "product\x00", string([]byte{0xff})} {
		if _, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", id, "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatal("invalid raw coordinate accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readCustomerPackageProvenanceTx(ctx, tx, "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCustomerPackageProvenanceSnapshotDoesNotWaitForWriterFence(t *testing.T) {
	s := customerProvenanceFixture(t)
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
	v, err := readCustomerPackageProvenanceTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v["builds"].([]map[string]any)) != 1 || len(v["build_attestations"].([]map[string]any)) != 1 {
		t.Fatalf("reader blocked by writer fence/locks: %#v err=%v", v, err)
	}
}

func TestCustomerPackageProvenanceSnapshotRejectsIncoherentParents(t *testing.T) {
	s := customerProvenanceFixture(t)
	for _, tc := range []struct {
		name, sql, restore string
		builds             int
	}{
		{"build project", `UPDATE build_runs SET project_id='sibling_project' WHERE id='build'`, `UPDATE build_runs SET project_id='project' WHERE id='build'`, 0},
		{"build release", `UPDATE build_runs SET release_id='sibling_release' WHERE id='build'`, `UPDATE build_runs SET release_id='release' WHERE id='build'`, 0},
		{"missing collector", `UPDATE build_runs SET collector_id='missing' WHERE id='build'`, `UPDATE build_runs SET collector_id='collector' WHERE id='build'`, 0},
		{"foreign collector", `UPDATE build_runs SET collector_id='foreign_collector' WHERE id='build'`, `UPDATE build_runs SET collector_id='collector' WHERE id='build'`, 0},
		{"foreign artifact", `UPDATE build_runs SET outputs='[{"artifact_id":"foreign_artifact","digest":"sha256:foreign"}]' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`, 0},
		{"artifact digest", `UPDATE build_runs SET outputs='[{"artifact_id":"artifact_build","digest":"sha256:wrong"}]' WHERE id='build'`, `UPDATE build_runs SET outputs='[]' WHERE id='build'`, 0},
		{"source tenant", `UPDATE evidence_items SET tenant_id='foreign_tenant' WHERE id='attestation_source'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='attestation_source'`, 1},
		{"source product", `UPDATE evidence_items SET product_id='sibling' WHERE id='attestation_source'`, `UPDATE evidence_items SET product_id='product' WHERE id='attestation_source'`, 1},
		{"source project", `UPDATE evidence_items SET project_id='sibling_project' WHERE id='attestation_source'`, `UPDATE evidence_items SET project_id='project' WHERE id='attestation_source'`, 1},
		{"source release", `UPDATE evidence_items SET release_id='sibling_release' WHERE id='attestation_source'`, `UPDATE evidence_items SET release_id='release' WHERE id='attestation_source'`, 1},
		{"source build", `UPDATE evidence_items SET build_id='sibling_build' WHERE id='attestation_source'`, `UPDATE evidence_items SET build_id='build' WHERE id='attestation_source'`, 1},
		{"source type", `UPDATE evidence_items SET type='document' WHERE id='attestation_source'`, `UPDATE evidence_items SET type='build_attestation' WHERE id='attestation_source'`, 1},
		{"source hash", `UPDATE evidence_items SET payload_hash='sha256:wrong' WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_hash='sha256:attestation' WHERE id='attestation_source'`, 1},
		{"source size", `UPDATE evidence_items SET payload_size=8 WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_size=7 WHERE id='attestation_source'`, 1},
		{"source storage", `UPDATE evidence_items SET payload_ref='private-other-payload-marker' WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_ref='private-payload-marker' WHERE id='attestation_source'`, 1},
		{"source deployment", `UPDATE evidence_items SET deployment_id='missing' WHERE id='attestation_source'`, `UPDATE evidence_items SET deployment_id=NULL WHERE id='attestation_source'`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			v, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v["builds"].([]map[string]any)) != tc.builds || len(v["build_attestations"].([]map[string]any)) != 0 || tx.privateFound {
				t.Fatalf("incoherent provenance=%#v private=%v err=%v", v, tx.privateFound, err)
			}
		})
	}
}

func TestCustomerPackageProvenanceSnapshotPreservesNullListsAndIntegerPrecision(t *testing.T) {
	s := customerProvenanceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE build_runs SET outputs='null' WHERE id='build'; UPDATE build_attestations SET subject_digests='null',payload_size=4611686018427387907 WHERE id='attestation'; UPDATE evidence_items SET payload_size=4611686018427387907 WHERE id='attestation_source'`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageProvenanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	build := v["builds"].([]map[string]any)[0]
	attestation := v["build_attestations"].([]map[string]any)[0]
	if outputs := build["outputs"].([]map[string]any); outputs == nil || len(outputs) != 0 {
		t.Fatal("legacy null outputs changed", outputs)
	}
	if subjects := attestation["subject_digests"].([]string); subjects != nil || attestation["payload_size"].(json.Number).String() != "4611686018427387907" {
		t.Fatal("legacy subjects/integer precision changed", attestation)
	}
}

func TestCustomerPackageProvenanceSnapshotBoundsBuildAndAttestationRows(t *testing.T) {
	for _, kind := range []string{"build", "attestation"} {
		t.Run(kind, func(t *testing.T) {
			s := customerProvenanceFixture(t)
			insert := `INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,started_at,status,outputs,schema_version,created_at)
			 SELECT 'overflow_'||n,'tenant','project','release','test','commit','2026-10-01T00:00:00Z','passed','[]','build.v1','2026-10-01T00:00:00Z' FROM generate_series(1,4096)n`
			table, section := "build_runs", "builds"
			if kind == "attestation" {
				insert = `INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version,created_at)
				 SELECT 'overflow_'||n,'tenant','build','attestation_source','private-payload-marker','sha256:attestation',7,'type','predicate','[]',0,0,'accepted','attestation.v1','2026-10-01T00:00:00Z' FROM generate_series(1,4096)n`
				table, section = "build_attestations", "build_attestations"
			}
			if _, err := s.pool.Exec(t.Context(), insert); err != nil {
				t.Fatal(err)
			}
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageProvenanceTx(t.Context(), tx, "tenant", "product", "release", customerProvenanceProfile(), budget)
			if !errors.Is(err, packageapp.ErrConflict) || v != nil || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.privateFound || tx.largest > 4096 {
				t.Fatalf("row overflow result=%#v budget=%d transfer=%d err=%v", v, budget.remainingBytes, tx.largest, err)
			}
			// Closed fixture-controlled names only, never operator/request text.
			if _, err := s.pool.Exec(t.Context(), "DELETE FROM "+table+" WHERE id='overflow_4096'"); err != nil {
				t.Fatal(err)
			}
			v, err = readCustomerPackageProvenanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerProvenanceProfile(), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v[section].([]map[string]any)) != packageapp.MaxSecurityReviewEvidenceIDs {
				t.Fatalf("exact row limit rejected: section=%s result=%#v err=%v", section, v, err)
			}
		})
	}
}
