package postgres

import (
	"errors"
	"testing"
	"time"

	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestReadEvidenceFlowSnapshotCountsCurrentTenantRowsWithoutLoadingLedger(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenantID := range []string{"ten_flow", "ten_foreign"} {
		exec(`INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, now)
	}
	exec(`INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ('prod_flow', 'ten_flow', 'Flow', 'flow', $1)`, now)
	exec(`INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ('proj_flow', 'ten_flow', 'prod_flow', 'Flow', $1)`, now)
	exec(`INSERT INTO releases (id, tenant_id, product_id, version, state, revision, created_at)
		VALUES ('rel_flow', 'ten_flow', 'prod_flow', '1.0.0', 'draft', 1, $1)`, now)
	for _, evidence := range []struct{ id, tenantID string }{
		{"ev_sbom", "ten_flow"}, {"ev_scan", "ten_flow"}, {"ev_vex", "ten_flow"},
		{"ev_attestation", "ten_flow"}, {"ev_foreign", "ten_foreign"},
	} {
		exec(`INSERT INTO evidence_items (
			id, tenant_id, type, title, source_system, observed_at, schema_version,
			payload_hash, canonical_hash, canonicalization, trust_level, verification_status
		) VALUES ($1, $2, 'test', 'Flow fixture', 'test', $3, 'evidence.v1',
			'sha256:fixture', 'sha256:fixture', 'json', 'unverified', 'recorded')`, evidence.id, evidence.tenantID, now)
	}
	exec(`INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components)
		VALUES ('sbom_flow', 'ten_flow', 'ev_sbom', 'rel_flow', 'art_a', 'cyclonedx', '1.6', 0, '[]')`)
	exec(`INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components)
		VALUES ('sbom_foreign', 'ten_foreign', 'ev_foreign', 'rel_flow', 'art_foreign', 'cyclonedx', '1.6', 0, '[]')`)
	exec(`INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, scanner, target_ref, summary, findings, release_id)
		VALUES ('scan_flow', 'ten_flow', 'ev_scan', 'generic', 'target', '{}', '[]', 'rel_flow')`)
	exec(`INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, scanner, target_ref, summary, findings, release_id)
		VALUES ('scan_foreign', 'ten_foreign', 'ev_foreign', 'generic', 'target', '{}', '[]', 'rel_flow')`)
	exec(`INSERT INTO vex_documents (id, tenant_id, evidence_id, release_id, artifact_id, format, author, statement_count, status_summary, schema_version)
		VALUES ('vex_flow', 'ten_flow', 'ev_vex', 'rel_flow', 'art_a', 'openvex', 'tester', 0, '{}', 'vex.v1')`)
	exec(`INSERT INTO vulnerability_decisions (id, tenant_id, finding_id, scan_id, release_id, vulnerability, status, justification, source, schema_version)
		VALUES ('decision_flow', 'ten_flow', 'finding_1', 'scan_flow', 'rel_flow', 'CVE-2026-0001', 'not_affected', 'reviewed', 'manual', 'decision.v1')`)
	exec(`INSERT INTO vulnerability_decisions (id, tenant_id, finding_id, scan_id, release_id, vulnerability, status, justification, source, schema_version, superseded_by)
		VALUES ('decision_old', 'ten_flow', 'finding_1', 'scan_flow', 'rel_flow', 'CVE-2026-0001', 'affected', 'old', 'manual', 'decision.v1', 'decision_flow')`)
	exec(`INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version)
		VALUES ('build_pass', 'ten_flow', 'proj_flow', 'rel_flow', 'generic_ci', 'abc', 'passed', $1,
			'[{"artifact_id":"art_a","digest":"sha256:a"},{"artifact_id":"art_b","digest":"sha256:b"}]', 'build.v1')`, now)
	exec(`INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version)
		VALUES ('build_fail', 'ten_flow', 'proj_flow', 'rel_flow', 'generic_ci', 'def', 'failed', $1,
			'[{"artifact_id":"art_c","digest":"sha256:c"}]', 'build.v1')`, now)
	exec(`INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version)
		VALUES ('build_foreign', 'ten_foreign', 'proj_flow', 'rel_flow', 'generic_ci', 'ghi', 'passed', $1,
			'[{"artifact_id":"art_foreign","digest":"sha256:d"}]', 'build.v1')`, now)
	exec(`INSERT INTO build_attestations (id, tenant_id, build_id, evidence_id, payload_hash, payload_size, payload_type,
		predicate_type, subject_digests, materials_count, signature_count, verification_status, schema_version)
		VALUES ('att_flow', 'ten_flow', 'build_pass', 'ev_attestation', 'sha256:fixture', 1, 'application/json',
			'provenance', '[]', 0, 0, 'recorded', 'attestation.v1')`)
	exec(`INSERT INTO build_attestations (id, tenant_id, build_id, evidence_id, payload_hash, payload_size, payload_type,
		predicate_type, subject_digests, materials_count, signature_count, verification_status, schema_version)
		VALUES ('att_foreign', 'ten_foreign', 'build_pass', 'ev_foreign', 'sha256:fixture', 1, 'application/json',
			'provenance', '[]', 0, 0, 'recorded', 'attestation.v1')`)
	exec(`INSERT INTO release_bundles (id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs)
		VALUES ('bundle_flow', 'ten_flow', 'rel_flow', 'created', '{}', 'sha256:fixture', '[]')`)
	exec(`INSERT INTO customer_security_packages (id, tenant_id, product_id, release_id, redaction_profile_id,
		title, state, manifest, manifest_hash, expires_at, schema_version, created_at)
		VALUES ('package_flow', 'ten_flow', 'prod_flow', 'rel_flow', 'profile_flow', 'Flow', 'created', '{}', 'sha256:fixture', $1, 'package.v1', $2)`, now.Add(time.Hour), now)
	snapshot, err := store.ReadEvidenceFlowSnapshot(ctx, "ten_flow", "rel_flow")
	if err != nil || snapshot.TenantID != "ten_flow" || snapshot.ReleaseID != "rel_flow" || snapshot.ProductID != "prod_flow" {
		t.Fatalf("flow snapshot=%#v err=%v", snapshot, err)
	}
	want := map[string]int{
		"artifact_refs": 3, "passed_builds": 1, "build_attestations": 1,
		"sboms": 1, "vulnerability_scans": 1, "vex_documents": 1,
		"vulnerability_decisions": 1, "release_bundles": 1, "customer_packages": 1,
	}
	for key, count := range want {
		if snapshot.Counts[key] != count {
			t.Fatalf("%s count=%d, want %d: %#v", key, snapshot.Counts[key], count, snapshot.Counts)
		}
	}
	if _, err := store.ReadEvidenceFlowSnapshot(ctx, "ten_foreign", "rel_flow"); !errors.Is(err, releasequery.ErrNotFound) {
		t.Fatalf("foreign tenant flow err=%v, want not found", err)
	}
	if _, err := store.ReadEvidenceFlowSnapshot(ctx, "ten_flow", " "); !errors.Is(err, releasequery.ErrValidation) {
		t.Fatalf("blank release err=%v, want validation", err)
	}
}
