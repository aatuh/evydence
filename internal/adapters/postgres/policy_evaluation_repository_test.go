package postgres

import (
	"testing"
	"time"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPolicyEvaluationUOWPreservesExistingVerificationReaders(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	uow, err := store.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uow.Rollback(t.Context()) }()
	v := uow.Repositories().Verification
	if _, ok := v.(verificationapp.EvidenceVerificationReader); !ok {
		t.Fatal("evidence verification reader hidden")
	}
	if _, ok := v.(verificationapp.ReleaseBundleVerificationReader); !ok {
		t.Fatal("bundle verification reader hidden")
	}
	if _, ok := v.(verificationapp.AuditChainVerificationReader); !ok {
		t.Fatal("audit verification reader hidden")
	}
	if _, ok := v.(verificationapp.DSSEVerificationReader); !ok {
		t.Fatal("DSSE verification reader hidden")
	}
	if _, ok := v.(verificationapp.CosignSnapshotReader); !ok {
		t.Fatal("Cosign verification reader hidden")
	}
	if _, ok := v.(verificationapp.ArtifactSignatureVerificationReader); !ok {
		t.Fatal("artifact signature reader hidden")
	}
	if _, ok := v.(verificationapp.MerkleVerificationReader); !ok {
		t.Fatal("Merkle verification reader hidden")
	}
	if _, ok := v.(verificationapp.BackupVerificationReader); !ok {
		t.Fatal("backup verification reader hidden")
	}
}

func TestPolicyEvaluationSnapshotUsesItsActiveCommandTransaction(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Tenant');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`); err != nil {
		t.Fatal(err)
	}
	uow, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uow.Rollback(ctx) }()
	if _, err := uow.(*unitOfWork).tx.Exec(ctx, `INSERT INTO evidence_items(id,tenant_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)VALUES('evidence','tenant','release','sbom','SBOM','test',now(),'evidence.v1','sha256:test','sha256:test','json','L2','pending')`); err != nil {
		t.Fatal(err)
	}
	reader := uow.Repositories().PolicyEvaluationReader
	if reader == nil {
		t.Fatal("command snapshot reader missing")
	}
	inside, err := reader.ReadPolicyEvaluationSnapshot(ctx, "tenant", "release", time.Now().UTC())
	if err != nil || !inside.HasSBOM {
		t.Fatal("command read a separate snapshot", inside, err)
	}
	outside, err := store.ReadReleaseReadinessSnapshot(ctx, "tenant", "release")
	if err != nil || outside.HasSBOM {
		t.Fatal("uncommitted evidence escaped", outside, err)
	}
	if err := uow.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	outside, err = store.ReadReleaseReadinessSnapshot(ctx, "tenant", "release")
	if err != nil || outside.HasSBOM {
		t.Fatal("rollback retained evidence", outside, err)
	}
}
