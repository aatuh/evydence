package app

import (
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneReleaseStateCommandsCommitFreezeAndApprovalWithAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	release := releasedomain.Release{ID: "rel_state", TenantID: fixture.actor.TenantID, ProductID: "prod_state", Version: "1.0.0", Revision: 1, State: state, CreatedAt: fixture.now}
	fixture.reader.products[release.ProductID] = releasedomain.Product{ID: release.ProductID, TenantID: fixture.actor.TenantID, Slug: "state"}
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.releases[release.ID] = release
	fixture.transactions.state.products[release.ProductID] = fixture.reader.products[release.ProductID]
	commands, err := NewReleaseStateCommands(ReleaseStateCommandConfig{
		Reader: legacyReleaseStateReader{source: fixture.reader}, Authorizer: fixture.authorizer,
		Transactions: releaseStateTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_state" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commands.FreezeRelease(t.Context(), fixture.actor, release.ID, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale freeze err=%v, want conflict", err)
	} else if current, ok := CurrentRevision(err); !ok || current != 1 {
		t.Fatalf("stale freeze revision=%d ok=%t", current, ok)
	}
	frozen, err := commands.FreezeRelease(t.Context(), fixture.actor, release.ID, 1)
	if err != nil || frozen.State.String() != releasedomain.ReleaseStateFrozenValue || frozen.Revision != 2 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("freeze=%#v err=%v audit=%#v", frozen, err, fixture.transactions.state.audit)
	}
	fixture.reader.releases[release.ID] = frozen
	approved, err := commands.ApproveRelease(t.Context(), fixture.actor, release.ID, 2)
	if err != nil || approved.State.String() != releasedomain.ReleaseStateApprovedValue || approved.Revision != 3 || len(fixture.transactions.state.audit) != 2 {
		t.Fatalf("approve=%#v err=%v audit=%#v", approved, err, fixture.transactions.state.audit)
	}
	if fixture.transactions.state.releases[release.ID].Revision != 3 {
		t.Fatalf("state not committed: %#v", fixture.transactions.state.releases[release.ID])
	}
}

func TestStandaloneReleaseStateCommandsRejectForeignTenantAndRollBackAuditFailure(t *testing.T) {
	fixture := newServiceFixture(t)
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	release := releasedomain.Release{ID: "rel_state", TenantID: fixture.actor.TenantID, ProductID: "prod_state", Version: "1.0.0", Revision: 1, State: state, CreatedAt: fixture.now}
	fixture.reader.products[release.ProductID] = releasedomain.Product{ID: release.ProductID, TenantID: fixture.actor.TenantID, Slug: "state"}
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.releases[release.ID] = release
	fixture.transactions.state.products[release.ProductID] = fixture.reader.products[release.ProductID]
	commands, err := NewReleaseStateCommands(ReleaseStateCommandConfig{
		Reader: legacyReleaseStateReader{source: fixture.reader}, Authorizer: fixture.authorizer,
		Transactions: releaseStateTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_state" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	foreign := fixture.actor
	foreign.TenantID = "ten_foreign"
	if _, err := commands.FreezeRelease(t.Context(), foreign, release.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign freeze err=%v, want not found", err)
	}
	fixture.transactions.auditErr = errors.New("audit unavailable")
	if _, err := commands.FreezeRelease(t.Context(), fixture.actor, release.ID, 1); err == nil {
		t.Fatal("freeze succeeded without audit")
	}
	if fixture.transactions.state.releases[release.ID].Revision != 1 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("freeze escaped rollback: %#v", fixture.transactions.state)
	}
}

func TestReleaseStateCommandsRecheckParentAndAuthorizationBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fakeState, *fakeAuthorizer)
		want error
	}{
		{"removed parent", func(s *fakeState, _ *fakeAuthorizer) { delete(s.products, "product") }, ErrNotFound},
		{"foreign parent", func(s *fakeState, _ *fakeAuthorizer) {
			p := s.products["product"]
			p.TenantID = "other"
			s.products[p.ID] = p
		}, ErrNotFound},
		{"slug drift", func(s *fakeState, _ *fakeAuthorizer) {
			p := s.products["product"]
			p.Slug = "changed"
			s.products[p.ID] = p
		}, ErrConflict},
		{"revoked authorization", func(_ *fakeState, a *fakeAuthorizer) { a.err = application.ErrForbidden }, application.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			state, _ := releasedomain.ParseReleaseState("draft")
			product := releasedomain.Product{ID: "product", TenantID: fixture.actor.TenantID, Slug: "product"}
			release := releasedomain.Release{ID: "release", TenantID: fixture.actor.TenantID, ProductID: product.ID, Version: "1", State: state, Revision: 1, CreatedAt: fixture.now}
			fixture.reader.products[product.ID], fixture.transactions.state.products[product.ID] = product, product
			fixture.reader.releases[release.ID], fixture.transactions.state.releases[release.ID] = release, release
			fixture.transactions.beforeCommand = func(s *fakeState) { tc.edit(s, fixture.authorizer) }
			v, err := fixture.service.FreezeRelease(t.Context(), fixture.actor, release.ID, 1)
			if !errors.Is(err, tc.want) || v.ID != "" || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || fixture.transactions.state.releases[release.ID].Revision != 1 || len(fixture.transactions.state.audit) != 0 {
				t.Fatal("transition escaped parent/auth recheck", v, err, fixture.transactions)
			}
		})
	}
}
