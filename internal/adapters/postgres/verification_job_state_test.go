package postgres

import (
	"testing"
	"time"
)

func TestPostgresWorkerVerificationReadsOnlyClaimedTenantResult(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_verify", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant string }{{"vr_good", "ten_verify"}, {"vr_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO verification_results (id, tenant_id, subject_type, subject_id, result, checks, verified_at) VALUES ($1, $2, 'release_bundle', 'bun_a', 'passed', '[]'::jsonb, $3)`, row.id, row.tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO verification_results (id, tenant_id, subject_type, subject_id, result, checks, verified_at) VALUES ('vr_chain', 'ten_verify', 'audit_chain', '', 'passed', '[]'::jsonb, $1)`, now); err != nil {
		t.Fatal(err)
	}
	job := ClaimedJob{TenantID: "ten_verify", Kind: "verify_subject", SubjectType: "release_bundle", SubjectID: "bun_a", Payload: map[string]any{"result_id": "vr_good"}}
	state, ok, err := store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Verifications) != 1 || state.Verifications["vr_good"].Result != "passed" {
		t.Fatalf("focused verification state=%#v ok=%v error=%v", state.Verifications, ok, err)
	}
	job.Payload["result_id"] = "vr_other"
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Verifications) != 0 {
		t.Fatalf("foreign verification state=%#v ok=%v error=%v", state.Verifications, ok, err)
	}
	job.Payload["result_id"] = "vr_good"
	job.SubjectID = "bun_other"
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Verifications) != 0 {
		t.Fatalf("wrong subject state=%#v ok=%v error=%v", state.Verifications, ok, err)
	}
	chainJob := ClaimedJob{TenantID: "ten_verify", Kind: "verify_subject", SubjectType: "audit_chain", Payload: map[string]any{"result_id": "vr_chain"}}
	state, ok, err = store.LoadWorkerJobState(ctx, chainJob)
	if err != nil || !ok || len(state.Verifications) != 1 || state.Verifications["vr_chain"].SubjectID != "" {
		t.Fatalf("audit-chain verification state=%#v ok=%v error=%v", state.Verifications, ok, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE verification_results SET checks = '{}'::jsonb WHERE id = 'vr_good'`); err != nil {
		t.Fatal(err)
	}
	job.SubjectID = "bun_a"
	if _, _, err := store.LoadWorkerJobState(ctx, job); err == nil {
		t.Fatal("malformed verification checks were accepted")
	}
}
