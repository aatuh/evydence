package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingIntegrityRepository struct{ IntegrityRepository }

func (failingIntegrityRepository) InsertSigningProvider(context.Context, domain.SigningProvider) error {
	return errInjectedRepositoryFailure
}

func TestSigningProviderUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	provider, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "Tenant KMS", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true})
	if err != nil {
		t.Fatalf("create signing provider: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.SigningProviders[provider.ID]; !ok || got.TenantID != actor.TenantID || got.KeyRef != provider.KeyRef {
		t.Fatalf("signing provider not committed: %#v", snapshot.SigningProviders)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid signing provider err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertSigningProvider(ctx, provider)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate signing provider err=%v, want conflict", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingIntegrityRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "Failed KMS", Type: "gcp_kms", KeyRef: "projects/test/locations/global/keyRings/ring/cryptoKeys/key", Encrypted: true}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed signing provider err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.SigningProviders) != len(before.SigningProviders) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.signingProviders) != len(before.SigningProviders) {
		t.Fatalf("failed signing provider published state: before=%#v after=%#v", before, after)
	}
}
