package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestReleaseBundleSnapshotReadsOnlyCommittedScopedMetadata(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('ten_bundle','Bundle'),('ten_other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('prod_bundle','ten_bundle','Bundle','bundle'),('prod_other','ten_other','Other','other')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('rel_bundle','ten_bundle','prod_bundle','1.2.3','draft'),('rel_other','ten_other','prod_other','1','draft'),('rel_bad_parent','ten_bundle','prod_other','bad','draft')`)
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref)
		VALUES('ev_z','ten_bundle','prod_bundle','rel_bundle','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('ev_a','ten_bundle','prod_bundle','rel_bundle','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('ev_other','ten_other','prod_other','rel_other','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload')`, now)
	exec(`INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,object_key,mode,retention_days,status,schema_version,created_at,verification_expires_at,verification_checks,verification_limitations,verification_bucket)
		VALUES('ret_bundle','ten_bundle','Retention','private-prefix','private-object-key','COMPLIANCE',30,'verified','retention.v2',$1,$2,'[{"name":"provider","result":"passed","detail":"observed"}]',ARRAY['scope limit'],'private-bucket'),('ret_other','ten_other','Other','','','GOVERNANCE',1,'configured','retention.v2',$1,NULL,'[]','{}','')`, now, now.Add(-time.Hour))
	for _, id := range []string{"rel_other", "rel_bad_parent", "missing"} {
		if _, err := store.ReadReleaseBundleSnapshot(ctx, "ten_bundle", id, now); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	snapshot, err := store.ReadReleaseBundleSnapshot(ctx, "ten_bundle", "rel_bundle", now)
	if err != nil || snapshot.SnapshotVersion != packageapp.ReleaseBundleSnapshotVersion || snapshot.TenantID != "ten_bundle" || snapshot.ProductID != "prod_bundle" || snapshot.ReleaseVersion != "1.2.3" || snapshot.ReleaseState != "draft" || strings.Join(snapshot.EvidenceIDs, ",") != "ev_a,ev_z" || snapshot.ChainSequence != 0 || len(snapshot.ObjectLockProofs) != 1 || snapshot.ObjectLockProofs[0]["status"] != "stale" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-title", "private-payload", "private-prefix", "private-object-key", "private-bucket", "ev_other", "ret_other"} {
		if strings.Contains(string(body), private) {
			t.Fatalf("leaked %s", private)
		}
	}
	// Uncommitted rows are never selected into the export snapshot.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `UPDATE releases SET version='uncommitted' WHERE id='rel_bundle'`); err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.ReadReleaseBundleSnapshot(ctx, "ten_bundle", "rel_bundle", now)
	if err != nil || snapshot.ReleaseVersion != "1.2.3" {
		t.Fatalf("uncommitted snapshot=%#v err=%v", snapshot, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// No receipts, signatures, jobs or audit records are created by a snapshot.
	var writes int
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM release_bundles)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&writes); err != nil || writes != 0 {
		t.Fatalf("writes=%d err=%v", writes, err)
	}
	for _, badSQL := range []string{
		`UPDATE releases SET version=repeat('x',4097) WHERE id='rel_bundle'`,
		`UPDATE object_retention_policies SET verification_limitations=ARRAY[repeat('x',8388609)] WHERE id='ret_bundle'`,
		`UPDATE object_retention_policies SET verification_checks='{}' WHERE id='ret_bundle'`,
		`UPDATE object_retention_policies SET verification_checks=(SELECT jsonb_agg(jsonb_build_object('name','check','result','passed')) FROM generate_series(1,4097)) WHERE id='ret_bundle'`,
		`UPDATE object_retention_policies SET verification_limitations=array_fill('limit'::text,ARRAY[4097]) WHERE id='ret_bundle'`,
		`UPDATE object_retention_policies SET verification_limitations=ARRAY[NULL::text] WHERE id='ret_bundle'`,
	} {
		exec(badSQL)
		if _, err := store.ReadReleaseBundleSnapshot(ctx, "ten_bundle", "rel_bundle", now); !errors.Is(err, packageapp.ErrConflict) {
			t.Fatalf("oversized/malformed snapshot err=%v", err)
		}
		exec(`UPDATE releases SET version='1.2.3' WHERE id='rel_bundle'`)
		exec(`UPDATE object_retention_policies SET verification_limitations='{}',verification_checks='[]' WHERE id='ret_bundle'`)
	}
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		SELECT 'overflow_'||n,'ten_bundle','prod_bundle','rel_bundle','document','Bounded','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending' FROM generate_series(1,$2) AS n`, now, packageapp.MaxBundleSnapshotRows-2)
	if _, err := store.ReadReleaseBundleSnapshot(ctx, "ten_bundle", "rel_bundle", now); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("row overflow did not fail closed", err)
	}
}

func TestReleaseBundleSnapshotUsesOneViewDuringConcurrentCommits(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC()
	for _, statement := range []string{
		`INSERT INTO tenants(id,name) VALUES('tenant','Snapshot')`,
		`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Snapshot','snapshot')`,
		`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','before','draft')`,
		`INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,canonical_entry_hash,previous_entry_hash,entry_hash,schema_version) VALUES('audit_1','tenant',1,'test','release','release','user','user',now(),'sha256:first','','sha256:first','audit.v2')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	read, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Rollback(context.WithoutCancel(ctx)) }()
	before, err := readReleaseBundleSnapshotTx(ctx, read, "tenant", "release", now)
	if err != nil || before.ChainSequence != 1 || before.ChainHeadHash != "sha256:first" || len(before.EvidenceIDs) != 0 || len(before.ObjectLockProofs) != 0 {
		t.Fatalf("before=%#v err=%v", before, err)
	}
	write, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = write.Rollback(context.WithoutCancel(ctx)) }()
	for _, statement := range []string{
		`UPDATE releases SET version='after' WHERE id='release'`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES('new_evidence','tenant','product','release','document','New','test',now(),'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending')`,
		`INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,canonical_entry_hash,previous_entry_hash,entry_hash,schema_version) VALUES('audit_2','tenant',2,'test','release','release','user','user',now(),'sha256:second','sha256:first','sha256:second','audit.v2')`,
	} {
		if _, err := write.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := write.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Every later read in the original transaction must still see its original
	// release, evidence set and audit head, despite the committed writer.
	stillBefore, err := readReleaseBundleSnapshotTx(ctx, read, "tenant", "release", now)
	if err != nil || stillBefore.ReleaseVersion != "before" || len(stillBefore.EvidenceIDs) != 0 || stillBefore.ChainSequence != 1 || stillBefore.ChainHeadHash != "sha256:first" {
		t.Fatalf("mixed snapshot=%#v err=%v", stillBefore, err)
	}
	if err := read.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.ReadReleaseBundleSnapshot(ctx, "tenant", "release", now)
	if err != nil || after.ReleaseVersion != "after" || len(after.EvidenceIDs) != 1 || after.ChainSequence != 2 || after.ChainHeadHash != "sha256:second" {
		t.Fatalf("after=%#v err=%v", after, err)
	}
}

func TestReleaseBundleSnapshotRejectsInvalidInputAndCancellation(t *testing.T) {
	store := &Store{}
	if _, err := store.ReadReleaseBundleSnapshot(t.Context(), "tenant", "release", time.Now()); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal(err)
	}
	live := isolatedRelationalTestStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := live.ReadReleaseBundleSnapshot(ctx, "tenant", "release", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
