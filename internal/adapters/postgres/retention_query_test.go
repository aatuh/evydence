package postgres

import (
	"testing"
	"time"
)

func TestReadRetentionRecordsKeepsTenantAndScopeInOneSnapshot(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_ret_a", "ten_ret_b"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO legal_holds (id,tenant_id,scope_type,scope_id,reason,owner,released_at,schema_version,created_at)
		VALUES ('hold_a_release','ten_ret_a','release','rel_a','review','legal',$1,'legal-hold.v1',$2),
		       ('hold_a_evidence','ten_ret_a','evidence','ev_a','audit','security',NULL,'legal-hold.v1',$2),
		       ('hold_b_release','ten_ret_b','release','rel_a','foreign','other',NULL,'legal-hold.v1',$2)
	`, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO retention_overrides (id,tenant_id,scope_type,scope_id,retention_until,reason,owner,schema_version,created_at)
		VALUES ('override_a_release','ten_ret_a','release','rel_a',$1,'review','legal','retention-override.v1',$2),
		       ('override_b_release','ten_ret_b','release','rel_a',$1,'foreign','other','retention-override.v1',$2)
	`, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}

	all, err := store.ReadRetentionRecords(ctx, "ten_ret_a", "", "ignored")
	if err != nil || len(all.LegalHolds) != 2 || len(all.RetentionOverrides) != 1 || all.RetentionOverrides[0].TenantID != "ten_ret_a" {
		t.Fatalf("tenant report=%#v err=%v", all, err)
	}
	scoped, err := store.ReadRetentionRecords(ctx, "ten_ret_a", "release", "rel_a")
	if err != nil || len(scoped.LegalHolds) != 1 || scoped.LegalHolds[0].ID != "hold_a_release" || scoped.LegalHolds[0].ReleasedAt == nil || len(scoped.RetentionOverrides) != 1 || scoped.RetentionOverrides[0].ID != "override_a_release" {
		t.Fatalf("scoped report=%#v err=%v", scoped, err)
	}
	foreign, err := store.ReadRetentionRecords(ctx, "ten_ret_b", "release", "rel_a")
	if err != nil || len(foreign.LegalHolds) != 1 || foreign.LegalHolds[0].ID != "hold_b_release" || len(foreign.RetentionOverrides) != 1 || foreign.RetentionOverrides[0].ID != "override_b_release" {
		t.Fatalf("other tenant report=%#v err=%v", foreign, err)
	}
}
