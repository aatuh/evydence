package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingSaaSProfileRepository struct{ FutureExtensionsRepository }

func (failingSaaSProfileRepository) InsertSaaSEditionProfile(context.Context, domain.SaaSEditionProfile) error {
	return errInjectedRepositoryFailure
}

func TestSaaSProfileUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	actor.Scopes = append(actor.Scopes, ScopeInstanceAdmin)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	profile, err := ledger.CreateSaaSEditionProfile(ctx, actor, CreateSaaSEditionProfileInput{Name: "hosted-eu", Region: "eu", AdminTenantID: actor.TenantID, IsolationModel: "shared-control-plane"})
	if err != nil {
		t.Fatalf("create SaaS profile: %v", err)
	}
	if _, ok := ledger.saasProfiles[profile.ID]; !ok || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("SaaS profile was not published after commit")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingSaaSProfileRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeProfiles, beforeChain := len(ledger.saasProfiles), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateSaaSEditionProfile(ctx, actor, CreateSaaSEditionProfileInput{Name: "failed", Region: "eu", AdminTenantID: actor.TenantID, IsolationModel: "shared-control-plane"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed SaaS profile err=%v, want injected repository failure", err)
	}
	if len(ledger.saasProfiles) != beforeProfiles || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed SaaS profile published cached state")
	}
}
