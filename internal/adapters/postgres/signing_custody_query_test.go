package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestPostgresSigningCustodyReadsOnlyBoundedTenantRecords(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('foreign','Foreign')`)
	exec(`INSERT INTO signing_providers(id,tenant_id,name,type,status,key_ref,encrypted,schema_version,created_at)VALUES
		('provider','tenant','HSM','native_pkcs11_hsm','configured','pkcs11:object=signing',true,'signing-provider.v1.0.0',$1),
		('foreign_provider','foreign',repeat('x',9*1024*1024),'aws_kms','configured','foreign-reference',true,'signing-provider.v1.0.0',$1)`, now)
	exec(`INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,object_key,require_legal_hold,mode,retention_days,status,verified_at,verification_hash,verification_checks,verification_limitations,max_verification_age_hours,verification_provider,verification_bucket,verification_mode,verification_retention_days,verification_legal_hold,verification_observed_at,verification_expires_at,schema_version,created_at)VALUES
		('policy','tenant','Lock','tenants/tenant/','tenants/tenant/raw/sample',true,'compliance',30,'verified',$1,'hash','[{"name":"provider","result":"passed"}]','{recorded}',24,'s3','bucket','compliance',30,true,$1,$2,'object-retention-policy.v2.0.0',$1)`, now.Add(-48*time.Hour), now.Add(-time.Hour))
	// No signing-key material belongs in this read, even if an unrelated row
	// is too large to select or malformed for other verification operations.
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,version,provider,algorithm,status,public_key,encrypted_private_key,valid_from,created_at)VALUES('unused','tenant','unused',1,'local_ed25519','Ed25519','active',repeat('x',9*1024*1024),'private-secret',$1,$1)`, now)
	query, err := verificationquery.NewSigningCustody(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"keys:admin"}}}}
	report, err := query.Report(ctx, actor)
	if err != nil || len(report.SigningProviders) != 1 || report.SigningProviders[0].ID != "provider" || len(report.ObjectRetentionPolicies) != 1 || report.ObjectRetentionPolicies[0].Status != "stale" || report.Checks[2].Result != "failed" {
		t.Fatalf("tenant report=%#v err=%v", report, err)
	}
	policy := report.ObjectRetentionPolicies[0]
	if policy.ObjectKey != "tenants/tenant/raw/sample" || policy.VerificationLegalHold == nil || !*policy.VerificationLegalHold || policy.VerificationProvider != "s3" || policy.VerificationBucket != "bucket" || len(policy.VerificationChecks) != 2 || len(policy.VerificationLimitations) != 2 {
		t.Fatalf("receipt fields lost %#v", policy)
	}
	var status string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM object_retention_policies WHERE id='policy'`).Scan(&status); err != nil || status != "verified" {
		t.Fatal("read mutated durable history", status, err)
	}
	exec(`UPDATE object_retention_policies SET verification_checks='{}' WHERE id='policy'`)
	if report, err := query.Report(ctx, actor); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) || report.TenantID != "" {
		t.Fatal("malformed receipt checks accepted", err)
	}
	exec(`UPDATE object_retention_policies SET verification_checks='[{"name":"provider","result":"passed"}]' WHERE id='policy'`)
	exec(`UPDATE signing_providers SET name=repeat('x',9*1024*1024) WHERE id='provider'`)
	actor.ResourceGrants[0].ResourceID = "foreign"
	if _, err := query.Report(ctx, actor); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("grant denial loaded oversized body", err)
	}
	actor.ResourceGrants[0].ResourceID = "tenant"
	if report, err := query.Report(ctx, actor); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) || report.TenantID != "" {
		t.Fatal("oversized provider accepted", err)
	}
	exec(`UPDATE signing_providers SET name=repeat('x',5*1024*1024) WHERE id='provider'`)
	exec(`UPDATE object_retention_policies SET verification_limitations=ARRAY[repeat('x',5*1024*1024)] WHERE id='policy'`)
	if _, err := query.Report(ctx, actor); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) {
		t.Fatal("combined byte limit not enforced", err)
	}
	exec(`UPDATE signing_providers SET name='HSM' WHERE id='provider';UPDATE object_retention_policies SET verification_limitations='{recorded}' WHERE id='policy'`)
	// Two different tables share one record budget. At the boundary both
	// provider and policy rows must be returned, with no hidden truncation.
	exec(`INSERT INTO signing_providers(id,tenant_id,name,type,status,key_ref,encrypted,schema_version,created_at)
		SELECT 'bulk_'||lpad(i::text,5,'0'),'tenant','Provider','aws_kms','configured','kms:key',true,'signing-provider.v1.0.0',$1 FROM generate_series(1,4094)i`, now)
	report, err = query.Report(ctx, actor)
	if err != nil || len(report.SigningProviders) != 4095 || len(report.ObjectRetentionPolicies) != 1 {
		t.Fatalf("exact row budget providers=%d policies=%d err=%v", len(report.SigningProviders), len(report.ObjectRetentionPolicies), err)
	}
	exec(`INSERT INTO signing_providers(id,tenant_id,name,type,status,key_ref,encrypted,schema_version,created_at)VALUES('over','tenant','Provider','aws_kms','configured','kms:key',true,'signing-provider.v1.0.0',$1)`, now)
	if report, err := query.Report(ctx, actor); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) || report.TenantID != "" {
		t.Fatal("combined row limit not enforced", err)
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs", "verification_results"} {
		var count int
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("read effects %s=%d err=%v", table, count, err)
		}
	}
}
