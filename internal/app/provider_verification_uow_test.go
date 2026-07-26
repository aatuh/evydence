package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingProviderVerificationRepository struct{ IdentityRepository }

func (failingProviderVerificationRepository) InsertProviderVerification(context.Context, domain.ProviderVerification) error {
	return errInjectedRepositoryFailure
}

func TestProviderVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("create SSO provider: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{Email: "user@example.test", DisplayName: "User"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "sub-1", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("link SSO identity: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	verification, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "sub-1"})
	if err != nil {
		t.Fatalf("verify provider identity: %v", err)
	}
	if ledger.providerVerifications[verification.ID].Profile.ID == "" || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("provider verification was not published after commit with its assurance profile")
	}
	failed, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "unlinked-subject"})
	if !errors.Is(err, ErrVerificationFailed) || ledger.providerVerifications[failed.ID].ID != failed.ID {
		t.Fatalf("failed provider verification = %#v err=%v, want persisted verification failure", failed, err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Identity = failingProviderVerificationRepository{IdentityRepository: repositories.Identity}
		return repositories
	}}
	beforeVerifications, beforeChain := len(ledger.providerVerifications), len(ledger.chain[actor.TenantID])
	if _, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: provider.ID, Subject: "sub-1"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed provider verification err=%v, want injected repository failure", err)
	}
	if len(ledger.providerVerifications) != beforeVerifications || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed provider verification published cached state")
	}
}
