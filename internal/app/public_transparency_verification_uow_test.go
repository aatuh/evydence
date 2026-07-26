package app

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingPublicTransparencyVerificationRepository struct{ FutureExtensionsRepository }

func (failingPublicTransparencyVerificationRepository) UpdatePublicTransparencyLogEntry(context.Context, domain.PublicTransparencyLogEntry, string) error {
	return errInjectedRepositoryFailure
}

func TestPublicTransparencyVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	log, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "public", Endpoint: "https://transparency.example.test", PublicKey: "public-key"})
	if err != nil {
		t.Fatalf("create public log: %v", err)
	}
	checkpoint, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "rfc3161", ExternalID: "checkpoint"})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	entry, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: checkpoint.ID, ExternalID: "entry"})
	if err != nil {
		t.Fatalf("publish entry: %v", err)
	}
	rootHash := transparencyVerificationRoot(t, entry.EntryHash)
	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	verified, err := ledger.VerifyPublicTransparencyLogEntry(ctx, actor, entry.ID, VerifyPublicTransparencyLogEntryInput{RootHash: rootHash, LeafIndex: 0, TreeSize: 1})
	if err != nil {
		t.Fatalf("verify entry: %v", err)
	}
	if verified.State != "inclusion_verified" || ledger.publicLogEntries[entry.ID].InclusionProofHash == "" || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatalf("verification was not published after commit: %#v", verified)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingPublicTransparencyVerificationRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	before, beforeChain := ledger.publicLogEntries[entry.ID], len(ledger.chain[actor.TenantID])
	if _, err := ledger.VerifyPublicTransparencyLogEntry(ctx, actor, entry.ID, VerifyPublicTransparencyLogEntryInput{RootHash: rootHash, LeafIndex: 0, TreeSize: 1}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed verification err=%v, want injected repository failure", err)
	}
	if got := ledger.publicLogEntries[entry.ID]; !reflect.DeepEqual(got, before) || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed verification published cached state")
	}
}

func transparencyVerificationRoot(t *testing.T, leafHash string) string {
	t.Helper()
	leaf, err := decodeSHA256Digest(leafHash)
	if err != nil {
		t.Fatalf("decode leaf hash: %v", err)
	}
	return "sha256:" + hex.EncodeToString(leaf[:])
}
