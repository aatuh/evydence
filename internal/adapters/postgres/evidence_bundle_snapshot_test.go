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

func TestEvidenceBundleSnapshotIsBoundedScopedAndOneCommittedView(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Snapshot'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Snapshot','snapshot'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','Project')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft'),('foreign_release','other','foreign','1','draft')`)
	exec(`INSERT INTO evidence_items(id,tenant_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,payload_ref)
	 VALUES('evidence','tenant','project','release','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload'),('foreign_evidence','other',NULL,'foreign_release','document','private-title','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending','private-payload')`, now)
	exec(`INSERT INTO object_retention_policies(id,tenant_id,name,object_prefix,object_key,mode,retention_days,status,schema_version,created_at,verification_bucket) VALUES('proof','tenant','Proof','private-prefix','private-key','GOVERNANCE',1,'configured','retention.v2',$1,'private-bucket')`, now)
	for _, release := range []string{"foreign_release", "missing"} {
		if _, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", release, now); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal(err)
		}
	}
	snapshot, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "release", now)
	if err != nil || snapshot.ProductID != "product" || len(snapshot.Evidence) != 1 || snapshot.Evidence[0].ID != "evidence" || snapshot.Evidence[0].Resources.ProductID != "product" || len(snapshot.ObjectLockProofs) != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-title", "private-payload", "private-prefix", "private-key", "private-bucket", "foreign_evidence"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("snapshot leaked", secret)
		}
	}
	read, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Rollback(context.WithoutCancel(ctx)) }()
	before, err := readEvidenceBundleSnapshotTx(ctx, read, "tenant", "release", now)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES('new','tenant','product','release','document','New','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending')`, now)
	exec(`INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,canonical_entry_hash,previous_entry_hash,entry_hash,schema_version) VALUES('audit','tenant',1,'test','release','release','user','user',$1,'sha256:head','','sha256:head','audit.v2')`, now)
	stillBefore, err := readEvidenceBundleSnapshotTx(ctx, read, "tenant", "release", now)
	if err != nil || len(stillBefore.Evidence) != len(before.Evidence) || stillBefore.AuditChainHead != before.AuditChainHead {
		t.Fatal("mixed committed view", err)
	}
	if err := read.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "release", now)
	if err != nil || len(after.Evidence) != 2 || after.AuditChainHead != "sha256:head" {
		t.Fatal("new committed view missing", err)
	}
	for _, mutation := range []string{
		`UPDATE projects SET product_id='foreign' WHERE id='project'`,
		`UPDATE evidence_items SET build_id=repeat('x',1025) WHERE id='evidence'`,
		`UPDATE object_retention_policies SET verification_limitations=ARRAY[repeat('x',8388609)] WHERE id='proof'`,
		`UPDATE object_retention_policies SET verification_checks='{}' WHERE id='proof'`,
	} {
		exec(mutation)
		if _, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "release", now); !errors.Is(err, packageapp.ErrConflict) {
			t.Fatal("invalid metadata accepted", err)
		}
		exec(`UPDATE projects SET product_id='product' WHERE id='project'`)
		exec(`UPDATE evidence_items SET build_id=NULL WHERE id='evidence'`)
		exec(`UPDATE object_retention_policies SET verification_limitations='{}',verification_checks='[]' WHERE id='proof'`)
	}
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
	 SELECT 'overflow_'||n,'tenant','product','release','document','Bounded','test',$1,'evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending' FROM generate_series(1,$2) AS n`, now, packageapp.MaxBundleSnapshotRows-2)
	if _, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "release", now); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("overflow was truncated", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ReadEvidenceBundleSnapshot(ctx, "tenant", "", now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
