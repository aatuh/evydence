package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingCosignVerificationRepository struct{ IntegrityRepository }

func (failingCosignVerificationRepository) InsertCosignVerification(context.Context, domain.CosignVerification) error {
	return errInjectedRepositoryFailure
}

func TestCosignVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	artifact, err := ledger.RegisterArtifact(ctx, actor, "cosign", "application/vnd.oci.image.manifest.v1+json", sampleDigest("cosign-artifact"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	if _, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/cosign", Digest: artifact.Digest}); err != nil {
		t.Fatalf("register image: %v", err)
	}
	signature, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "signature"})
	if err != nil {
		t.Fatalf("create artifact signature: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	record, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: signature.ID, RekorUUID: "rekor", RekorLogIndex: "1"})
	if err != nil {
		t.Fatalf("verify Cosign signature: %v", err)
	}
	if _, ok := ledger.cosignVerifs[record.ID]; !ok {
		t.Fatal("Cosign verification was not published after commit")
	}
	if _, ok := ledger.verifications[record.ID]; !ok {
		t.Fatal("normalized verification result was not published after commit")
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.CosignVerifications[record.ID]; !ok {
		t.Fatal("Cosign verification was not committed")
	}
	if _, ok := snapshot.VerificationResults[record.ID]; !ok {
		t.Fatal("normalized verification result was not committed")
	}
	if got := len(ledger.chain[actor.TenantID]); got != chainEntriesBefore+1 {
		t.Fatalf("Cosign audit entry was not published after commit: got %d, want %d", got, chainEntriesBefore+1)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingCosignVerificationRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	beforeCosign, beforeVerification := len(ledger.cosignVerifs), len(ledger.verifications)
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: signature.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed Cosign verification err=%v, want injected repository failure", err)
	}
	if len(ledger.cosignVerifs) != beforeCosign || len(ledger.verifications) != beforeVerification || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("failed Cosign verification published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.CosignVerifications) != len(before.CosignVerifications) || len(after.VerificationResults) != len(before.VerificationResults) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatal("failed Cosign verification committed durable state")
	}
}
