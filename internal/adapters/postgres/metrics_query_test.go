package postgres

import (
	"testing"
	"time"
)

func TestReadMetricsSnapshotFiltersTenantCountsAndGatesGlobalOutbox(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_metrics_a", "ten_metrics_b"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
			VALUES ($1,$2,'document',$1,'test',$3,'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')
		`, "ev_"+tenant, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO customer_portal_access (id,tenant_id,package_id,customer_name,prefix,hash,expires_at,revoked_at,failed_access_count,schema_version,created_at)
		VALUES ('portal_a','ten_metrics_a','pkg_a','A','prefix_a','hash_a',$1,$2,3,'customer-portal-access.v1.0.0',$2),
		       ('portal_b','ten_metrics_b','pkg_b','B','prefix_b','hash_b',$1,NULL,7,'customer-portal-access.v1.0.0',$2)
	`, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO object_reconciliation_receipts (id,tenant_id,dry_run,metadata_cursor,provider_cursor,scanned_payloads,healthy_payloads,missing_final_objects,missing_staged_objects,digest_mismatches,recovered_finalizations,abandoned_staging,provider_orphans,quarantined_payloads,created_at,schema_version)
		VALUES ('receipt_a','ten_metrics_a',false,0,0,5,4,1,0,0,0,0,0,1,$1,'object-reconciliation.v1'),
		       ('receipt_b','ten_metrics_b',false,0,0,9,9,0,0,0,0,0,0,0,$1,'object-reconciliation.v1')
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO outbox_jobs (id,tenant_id,kind,subject_type,subject_id,deduplication_key,status,created_at,updated_at)
		VALUES ('job_metrics_b','ten_metrics_b','parse_sbom','sbom','sbom_b','metrics-b','queued',$1,$1)
	`, now); err != nil {
		t.Fatal(err)
	}

	tenant, err := store.ReadMetricsSnapshot(ctx, "ten_metrics_a", false)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.ResourceCounts["evidence"] != 1 || tenant.CustomerPortalFailedAccessCount != 3 || tenant.CustomerPortalRevokedAccessCount != 1 || tenant.Reconciliation.Runs != 1 || tenant.Reconciliation.ScannedPayloads != 5 || tenant.Reconciliation.MissingFinalObjects != 1 || tenant.Outbox != nil {
		t.Fatalf("tenant metrics=%#v", tenant)
	}
	operator, err := store.ReadMetricsSnapshot(ctx, "ten_metrics_a", true)
	if err != nil || operator.Outbox == nil || operator.Outbox.PendingJobs != 1 || operator.Outbox.OldestPendingCreatedAt.IsZero() {
		t.Fatalf("operator metrics=%#v err=%v", operator, err)
	}
	other, err := store.ReadMetricsSnapshot(ctx, "ten_metrics_b", false)
	if err != nil || other.CustomerPortalFailedAccessCount != 7 || other.CustomerPortalRevokedAccessCount != 0 || other.Reconciliation.ScannedPayloads != 9 {
		t.Fatalf("other tenant metrics=%#v err=%v", other, err)
	}
}
