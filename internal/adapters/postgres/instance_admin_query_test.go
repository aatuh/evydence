package postgres

import (
	"testing"
	"time"
)

func TestPostgresInstanceAdminCountsCurrentRowsWithoutTenantFilter(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_operator_a", "ten_operator_b"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO human_users (id,tenant_id,email,display_name,status,schema_version,created_at) VALUES ($1,$2,$3,$1,'active','human-user.v1.0.0',$4)`, "usr_"+tenant, tenant, tenant+"@example.test", now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO collectors (id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version,created_at) VALUES ($1,$2,$1,'generic_ci','1',$1,'active','[]'::jsonb,'collector.v1.0.0',$3)`, "col_"+tenant, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ($1,$2,'document',$1,'test',$3,'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`, "ev_"+tenant, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := store.ReadInstanceCounts(ctx)
	if err != nil || counts.Tenants != 2 || counts.Users != 2 || counts.Collectors != 2 || counts.Evidence != 2 {
		t.Fatalf("instance counts=%#v error=%v", counts, err)
	}
}
