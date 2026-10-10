package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestSourceRepositoryNativeFixturePreflightUsesCurrentRequestedAndExistingParents(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	second, err := releaseSetup(ledger).CreateProject(t.Context(), owner.actor, owner.product.ID, "Private")
	if err != nil {
		t.Fatal(err)
	}
	private, err := (integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateSourceRepository(t.Context(), owner.actor, integrationapp.CreateSourceRepositoryInput{ProjectID: second.ID, Provider: "git", FullName: "fixture/private"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("repository preflight used aggregate clock") }})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: owner.project.ID, Scopes: []string{"source:write"}}}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: owner.project.ID, Provider: owner.repository.Provider, FullName: owner.repository.FullName}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), human, in); err != nil {
		t.Fatal("current owned repository/project missing from preflight", err)
	}
	in.Provider, in.FullName = private.Provider, private.FullName
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("reuse bypassed existing repository project grant", err)
	}
	in.ProjectID, in.Provider, in.FullName = foreign.project.ID, "git", "fixture/new"
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), owner.actor, in); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign requested project accepted", err)
	}
	in.ProjectID = ""
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("project grant authorized detached repository", err)
	}
	in.ProjectID = owner.project.ID
	factory.fail = true
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), owner.actor, in); err == nil {
		t.Fatal("preflight accepted failed read commit")
	}
	factory.fail = false
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("repository preflight wrote state", err)
	}
}

func TestSourceRepositoryNativeFixturePagesUseCurrentScopeAndDiscardFailedCommit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	_ = seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("repository page used aggregate clock") }})
	f := sourceRepositoryPageFixture{catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"source:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"source:read"}}}}
	req := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.ListPage(t.Context(), human, owner.project.ID, req, nil)
	if err != nil || !reflect.DeepEqual(page.Items, []integrationdomain.SourceRepository{integrationdomain.SourceRepository(owner.repository)}) || page.Next != nil {
		t.Fatal("current scoped source page lost full public DTO", err)
	}
	factory.fail = true
	if page, err := f.ListPage(t.Context(), human, owner.project.ID, req, nil); err == nil || !reflect.DeepEqual(page, appquery.Result[integrationdomain.SourceRepository]{}) {
		t.Fatal("failed source read exposed metadata", err)
	}
	factory.fail = false
	human.ResourceGrants = nil
	if page, err := f.ListPage(t.Context(), human, "", req, nil); err != nil || len(page.Items) != 0 {
		t.Fatal("revoked source grants exposed repository inventory", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.ListPage(cancelled, owner.actor, "", req, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("source query ignored cancellation", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("source page changed repository state", err)
	}
}

func TestSourceRepositoryNativeFixtureFailsWithoutTransactionRepositories(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "admin", Scopes: []string{"*"}}
	in := integrationapp.CreateSourceRepositoryInput{Provider: "git", FullName: "org/api"}
	if err := f.AuthorizeSourceRepositoryCreation(t.Context(), a, in); err == nil {
		t.Fatal("repository preflight accepted missing repositories")
	}
	if v, err := f.CreateSourceRepository(t.Context(), a, in); err == nil || !reflect.DeepEqual(v, integrationdomain.SourceRepository{}) {
		t.Fatal("missing repository transaction exposed created metadata", err)
	}
	q := sourceRepositoryPageFixture{catalogFixtureCommands{ledger: ledger}}
	req := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	if v, err := q.ListPage(t.Context(), a, "", req, nil); err == nil || !reflect.DeepEqual(v, appquery.Result[integrationdomain.SourceRepository]{}) {
		t.Fatal("missing repository transaction exposed a page", err)
	}
}

func TestSourceRepositoryNativeFixtureCreatesReusesAndRollsBackCurrentRecord(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	at := peripheralFixtureQueryClock()
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("repository creation used aggregate clock") }})
	clockCalls := 0
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: application.ClockFunc(func() time.Time { clockCalls++; return at })}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: owner.project.ID, Scopes: []string{"source:write"}}}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: owner.project.ID, Provider: "git", FullName: "org/new", CloneURL: "https://example.invalid/new.git", DefaultBranch: "main"}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.CreateSourceRepository(t.Context(), human, in)
	if err != nil || v.ID == "" || v.TenantID != human.TenantID || v.ProjectID != in.ProjectID || v.Provider != in.Provider || v.FullName != in.FullName || v.CloneURL != in.CloneURL || v.DefaultBranch != in.DefaultBranch || v.SchemaVersion != integrationdomain.SourceRepositorySchemaVersion || !v.CreatedAt.Equal(at) || clockCalls != 1 {
		t.Fatal("focused creation lost current ownership, full DTO or explicit clock", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.SourceRepositories) != len(before.SourceRepositories)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
		t.Fatal("repository and human audit were not atomic", err)
	}
	entry := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
	if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.SubjectID != v.ID || entry.EntryType != "source_repository.created" {
		t.Fatal("repository audit lost human principal")
	}
	in.CloneURL, in.DefaultBranch = "https://example.invalid/changed.git", "changed"
	if reused, err := f.CreateSourceRepository(t.Context(), human, in); err != nil || reused != v || clockCalls != 1 {
		t.Fatal("natural repository reuse modified original metadata or allocated time", err)
	}
	factory.fail = true
	in.FullName = "org/failed"
	if failed, err := f.CreateSourceRepository(t.Context(), human, in); err == nil || !reflect.DeepEqual(failed, integrationdomain.SourceRepository{}) {
		t.Fatal("failed repository commit exposed metadata", err)
	}
	factory.fail = false
	in.ProjectID = foreign.project.ID
	if failed, err := f.CreateSourceRepository(t.Context(), owner.actor, in); !errors.Is(err, app.ErrNotFound) || failed.ID != "" {
		t.Fatal("foreign project accepted repository creation", err)
	}
	in.ProjectID = ""
	if _, err := f.CreateSourceRepository(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("project grant authorized detached repository creation", err)
	}
	in.ProjectID = owner.project.ID
	human.ResourceGrants = nil
	if _, err := f.CreateSourceRepository(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked repository grant accepted creation", err)
	}
	final, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, final) {
		t.Fatal("reuse/failed/denied creation changed repository or audit state", err)
	}
}
