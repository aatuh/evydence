package app

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneReleaseCommandsRequireCurrentTenantOwnedProduct(t *testing.T) {
	fixture := newServiceFixture(t)
	parent := releasedomain.Product{ID: "prod_parent", TenantID: fixture.actor.TenantID, Name: "Parent", Slug: "parent", CreatedAt: fixture.now}
	fixture.reader.products[parent.ID] = parent
	fixture.transactions.state.products[parent.ID] = parent
	commands, err := NewReleaseCommands(ReleaseCommandConfig{
		Reader: fixture.reader, Authorizer: fixture.authorizer,
		Transactions: releaseCreationTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_standalone" }),
	})
	if err != nil {
		t.Fatalf("new release commands: %v", err)
	}
	release, err := commands.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: parent.ID, Version: " 1.0.0 "})
	if err != nil || release.ID != "rel_standalone" || release.ProductID != parent.ID || release.Version != "1.0.0" {
		t.Fatalf("create release=%#v err=%v", release, err)
	}
	if len(fixture.transactions.state.releases) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("release and audit were not committed together: %#v", fixture.transactions.state)
	}
	if _, err := commands.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: parent.ID, Version: "1.0.0"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate version err=%v, want conflict", err)
	}
	foreign := fixture.actor
	foreign.TenantID = "ten_foreign"
	before := fixture.transactions.calls
	if _, err := commands.CreateRelease(context.Background(), foreign, CreateReleaseInput{ProductID: parent.ID, Version: "2.0.0"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign parent err=%v, want not found", err)
	}
	if fixture.transactions.calls != before {
		t.Fatal("foreign parent opened a transaction")
	}
	fixture.transactions.beforeCommand = func(state *fakeState) {
		changed := state.products[parent.ID]
		changed.Slug = "changed"
		state.products[parent.ID] = changed
	}
	if _, err := commands.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: parent.ID, Version: "2.0.0"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("drifted parent err=%v, want conflict", err)
	}
	fixture.transactions.beforeCommand = nil
	fixture.transactions.auditErr = errAudit
	if _, err := commands.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: parent.ID, Version: "2.0.0"}); !errors.Is(err, errAudit) {
		t.Fatalf("audit failure err=%v, want audit error", err)
	}
	if len(fixture.transactions.state.releases) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit failure committed a release: %#v", fixture.transactions.state)
	}
}
