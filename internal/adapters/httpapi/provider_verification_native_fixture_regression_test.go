package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestProviderVerificationFixtureReadsRepositoryLinkWithoutAggregatePublication(t *testing.T) {
	ledger, factory, _ := providerVerificationRegressionLedger()
	owner := seedProviderVerificationFixture(t, ledger, "Native")
	link := domain.UserIdentityLink{ID: "repository-only-link", TenantID: owner.actor.TenantID, UserID: owner.user.ID, ProviderID: owner.provider.ID, Subject: "repository-only-subject", Email: owner.user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: owner.provider.CreatedAt}
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertUserIdentityLink(ctx, link)
	}); err != nil {
		t.Fatal(err)
	}
	f := providerVerificationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	v, err := f.VerifyProviderIdentity(t.Context(), owner.actor, identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: link.Subject})
	if err != nil || v.Result != "limited" || len(v.Checks) != 1 || v.Checks[0].Name != "verified_identity_link" || v.Checks[0].Result != "passed" {
		t.Fatal("receipt consulted stale identity-link cache", v.Result, v.Checks, err)
	}
	saved, err := factory.Snapshot()
	if err != nil || saved.ProviderVerifications[v.ID].Subject != link.Subject {
		t.Fatal("native receipt lost committed subject", err)
	}
}

func TestProviderVerificationNativeFixtureRebindRetainsLiveClientAndFixedClock(t *testing.T) {
	first, _, live := providerVerificationRegressionLedger()
	second, _, _ := providerVerificationRegressionLedger()
	s, err := newLegacyServerFixture(first)
	if err != nil {
		t.Fatal(err)
	}
	s.bindProviderVerificationFixtureResources(live, providerVerificationFixtureClock())
	s.bindLegacyLedgerFixture(second)
	f, ok := s.providerVerificationCommands.(providerVerificationFixtureCommands)
	if !ok || f.ledger != second || f.live != live || f.clock == nil || !f.clock.Now().Equal(peripheralFixtureQueryClock()) {
		t.Fatal("rebinding lost explicit native receipt dependencies")
	}
}
