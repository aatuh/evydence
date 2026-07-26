package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingSigningOperationRepository struct{ FutureExtensionsRepository }

func (failingSigningOperationRepository) InsertSigningOperation(context.Context, domain.Signature, domain.SigningOperation) error {
	return errInjectedRepositoryFailure
}

func TestSigningOperationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	provider, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true})
	if err != nil {
		t.Fatalf("create signing provider: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	op, err := ledger.CreateSigningOperation(ctx, actor, CreateSigningOperationInput{ProviderID: provider.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload"), ExternalSignature: "provider-receipt"})
	if err != nil {
		t.Fatalf("create signing operation: %v", err)
	}
	if _, ok := ledger.signatures[op.SignatureRef]; !ok || ledger.signingOperations[op.ID].ID != op.ID || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("signing operation was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingSigningOperationRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeSignatures, beforeOperations, beforeChain := len(ledger.signatures), len(ledger.signingOperations), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateSigningOperation(ctx, actor, CreateSigningOperationInput{ProviderID: provider.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("failed"), ExternalSignature: "failed-receipt"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed signing operation err=%v, want injected repository failure", err)
	}
	if len(ledger.signatures) != beforeSignatures || len(ledger.signingOperations) != beforeOperations || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed signing operation published cached state")
	}
}
