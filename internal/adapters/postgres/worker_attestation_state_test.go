package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestPostgresWorkerAttestationStateRequiresCurrentTenantProvenance(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:" + strings.Repeat("a", 64)
	for _, row := range []struct{ suffix, tenant string }{{"a", "ten_att"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, row.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+row.suffix, row.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, "proj_"+row.suffix, row.tenant, "prod_"+row.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+row.suffix, row.tenant, "prod_"+row.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO build_runs (id, tenant_id, project_id, release_id, provider, commit_sha, status, started_at, outputs, schema_version, created_at) VALUES ($1, $2, $3, $4, 'test', '0123456789abcdef', 'passed', $5, '[]'::jsonb, 'v1', $5)`, "bld_"+row.suffix, row.tenant, "proj_"+row.suffix, "rel_"+row.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, project_id, release_id, build_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, payload_size, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'build_attestation', 'Attestation', 'test', $7, 1, 'evidence-item.v1.0.0', $8, 5, $8, 'canonical-json.v1', 'L2', 'pending', $7)`, "ev_"+row.suffix, row.tenant, "prod_"+row.suffix, "proj_"+row.suffix, "rel_"+row.suffix, "bld_"+row.suffix, now, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO build_attestations (id, tenant_id, build_id, evidence_id, payload_hash, payload_size, payload_type, predicate_type, subject_digests, materials_count, signature_count, verification_status, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, 5, '', '', 'null'::jsonb, 0, 0, 'accepted', 'build-attestation.v1.0.0', $6)`, "att_"+row.suffix, row.tenant, "bld_"+row.suffix, "ev_"+row.suffix, hash, now); err != nil {
			t.Fatal(err)
		}
	}
	job := ClaimedJob{TenantID: "ten_att", Kind: "verify_attestation", SubjectType: "build_attestation", SubjectID: "att_a"}
	state, ok, err := store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 1 || state.BuildAttestations["att_a"].EvidenceID != "ev_a" {
		t.Fatalf("focused attestation state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	job.TenantID = "ten_other"
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 0 {
		t.Fatalf("foreign attestation state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	job.TenantID = "ten_att"
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET type = 'sbom' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 0 {
		t.Fatalf("wrong source type state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET type = 'build_attestation', payload_hash = $1 WHERE id = 'ev_a'`, "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 0 {
		t.Fatalf("wrong source digest state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET payload_hash = $1, payload_ref = 'object://tenants/ten_att/payloads/wrong' WHERE id = 'ev_a'`, hash); err != nil {
		t.Fatal(err)
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 0 {
		t.Fatalf("wrong source reference state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET payload_ref = NULL WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_runs SET project_id = 'proj_other' WHERE id = 'bld_a'`); err != nil {
		t.Fatal(err)
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.BuildAttestations) != 0 {
		t.Fatalf("foreign build project state=%#v ok=%v error=%v", state.BuildAttestations, ok, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_runs SET project_id = 'proj_a' WHERE id = 'bld_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE build_attestations SET subject_digests = '{}'::jsonb WHERE id = 'att_a'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadWorkerJobState(ctx, job); err == nil {
		t.Fatal("malformed attestation subject digests were accepted")
	}
}
