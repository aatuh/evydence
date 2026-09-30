package app

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneProjectCommandsRequireCurrentTenantOwnedParent(t *testing.T) {
	fixture := newServiceFixture(t)
	parent := releasedomain.Product{ID: "prod_parent", TenantID: fixture.actor.TenantID, Name: "Parent", Slug: "parent", CreatedAt: fixture.now}
	fixture.reader.products[parent.ID] = parent
	fixture.transactions.state.products[parent.ID] = parent
	commands, err := NewProjectCommands(ProjectCommandConfig{
		Reader: fixture.reader, Authorizer: fixture.authorizer,
		Transactions: releaseProjectTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_standalone" }),
	})
	if err != nil {
		t.Fatalf("new project commands: %v", err)
	}
	project, err := commands.CreateProject(context.Background(), fixture.actor, CreateProjectInput{ProductID: parent.ID, Name: " Project "})
	if err != nil || project.ID != "proj_standalone" || project.ProductID != parent.ID || project.Name != "Project" {
		t.Fatalf("create project=%#v err=%v", project, err)
	}
	if len(fixture.transactions.state.projects) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("project and audit were not committed together: %#v", fixture.transactions.state)
	}
	foreign := fixture.actor
	foreign.TenantID = "ten_foreign"
	before := fixture.transactions.calls
	if _, err := commands.CreateProject(context.Background(), foreign, CreateProjectInput{ProductID: parent.ID, Name: "Denied"}); !errors.Is(err, ErrNotFound) {
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
	if _, err := commands.CreateProject(context.Background(), fixture.actor, CreateProjectInput{ProductID: parent.ID, Name: "Drifted"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("drifted parent err=%v, want conflict", err)
	}
	fixture.transactions.beforeCommand = nil
	fixture.transactions.auditErr = errAudit
	if _, err := commands.CreateProject(context.Background(), fixture.actor, CreateProjectInput{ProductID: parent.ID, Name: "Rolled back"}); !errors.Is(err, errAudit) {
		t.Fatalf("audit failure err=%v, want audit error", err)
	}
	if len(fixture.transactions.state.projects) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit failure committed a project: %#v", fixture.transactions.state)
	}
}
