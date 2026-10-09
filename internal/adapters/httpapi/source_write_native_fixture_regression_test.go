package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestSourceWriteNativeFixturesUseCurrentRepositoryHeadAndAtomicHumanAudit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("source write used aggregate clock") }})
	at := peripheralFixtureQueryClock()
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: application.ClockFunc(func() time.Time { return at })}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"source:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: owner.project.ID, Scopes: []string{"source:write"}}}}
	commitIn := integrationapp.RecordSourceCommitInput{RepositoryID: owner.repository.ID, SHA: strings.Repeat("b", 40), Author: " Team ", Message: " exact message \x00 "}
	branchIn := integrationapp.UpsertSourceBranchInput{RepositoryID: owner.repository.ID, Name: "main", HeadCommitID: owner.head.ID, Protected: false, ProtectionHash: "new"}
	prIn := integrationapp.RecordPullRequestInput{RepositoryID: owner.repository.ID, ProviderID: "42", Title: "Change", State: "open", HeadCommitID: owner.head.ID}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeSourceCommitRecording(t.Context(), human, commitIn); err != nil {
		t.Fatal("current commit scope rejected", err)
	}
	if err := f.AuthorizeSourceBranchUpsert(t.Context(), human, branchIn); err != nil {
		t.Fatal("current head scope rejected", err)
	}
	if err := f.AuthorizePullRequestRecording(t.Context(), human, prIn); err != nil {
		t.Fatal("current pull-request scope rejected", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("source preflights changed state", err)
	}
	commit, err := f.RecordSourceCommit(t.Context(), human, commitIn)
	if err != nil || commit.ID == "" || commit.RepositoryID != owner.repository.ID || commit.Author != "Team" || commit.MessageHash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(commitIn.Message))) || !commit.CommittedAt.Equal(at) || !commit.CreatedAt.Equal(at) {
		t.Fatal("native commit lost exact message hash or explicit time", err)
	}
	branchIn.HeadCommitID = commit.ID
	branch, err := f.UpsertSourceBranch(t.Context(), human, branchIn)
	if err != nil || branch.ID == "" || branch.HeadCommitID != commit.ID || branch.Protected || branch.ProtectionHash != "new" {
		t.Fatal("native branch lost current commit or protection", err)
	}
	prIn.HeadCommitID = commit.ID
	pr, err := f.RecordPullRequest(t.Context(), human, prIn)
	if err != nil || pr.ID == "" || pr.HeadCommitID != commit.ID || pr.Provider != owner.repository.Provider || pr.ProviderID != prIn.ProviderID || pr.Title != prIn.Title || pr.State != prIn.State {
		t.Fatal("native pull-request lost current provider/head or public fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.SourceCommits) != len(before.SourceCommits)+1 || len(after.SourceBranches) != len(before.SourceBranches) || len(after.PullRequests) != len(before.PullRequests)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+3 {
		t.Fatal("source writes and audits did not commit together", err)
	}
	for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != human.UserID {
			t.Fatal("source audit lost human principal")
		}
	}
	if again, err := f.RecordSourceCommit(t.Context(), human, commitIn); err != nil || again != commit {
		t.Fatal("natural commit reuse lost original DTO", err)
	}
	factory.fail = true
	commitIn.SHA = strings.Repeat("c", 40)
	if v, err := f.RecordSourceCommit(t.Context(), human, commitIn); err == nil || !reflect.DeepEqual(v, integrationdomain.SourceCommit{}) {
		t.Fatal("failed commit exposed source metadata", err)
	}
	branchIn.ProtectionHash = "failed"
	if v, err := f.UpsertSourceBranch(t.Context(), human, branchIn); err == nil || !reflect.DeepEqual(v, integrationdomain.SourceBranch{}) {
		t.Fatal("failed branch commit exposed metadata", err)
	}
	if v, err := f.RecordPullRequest(t.Context(), human, prIn); err == nil || !reflect.DeepEqual(v, integrationdomain.PullRequest{}) {
		t.Fatal("failed pull-request commit exposed metadata", err)
	}
	factory.fail = false
	branchIn.HeadCommitID = foreign.head.ID
	if err := f.AuthorizeSourceBranchUpsert(t.Context(), human, branchIn); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("preflight accepted foreign/cross-repository head", err)
	}
	if _, err := f.UpsertSourceBranch(t.Context(), human, branchIn); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign/cross-repository head accepted", err)
	}
	human.ResourceGrants = nil
	if _, err := f.RecordSourceCommit(t.Context(), human, commitIn); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked source grant accepted write", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.RecordPullRequest(cancelled, owner.actor, prIn); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source command accepted", err)
	}
	final, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, final) {
		t.Fatal("reuse, failed or denied source writes changed state", err)
	}
}

func TestSourceWriteNativeFixturesFailClosedWithoutRepositories(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	commit := integrationapp.RecordSourceCommitInput{RepositoryID: "repository", SHA: strings.Repeat("a", 40)}
	branch := integrationapp.UpsertSourceBranchInput{RepositoryID: "repository", Name: "main"}
	pr := integrationapp.RecordPullRequestInput{RepositoryID: "repository", ProviderID: "42", Title: "Change", State: "open"}
	if err := f.AuthorizeSourceCommitRecording(t.Context(), a, commit); err == nil {
		t.Fatal("commit preflight accepted missing repository factory")
	}
	if err := f.AuthorizeSourceBranchUpsert(t.Context(), a, branch); err == nil {
		t.Fatal("branch preflight accepted missing repository factory")
	}
	if err := f.AuthorizePullRequestRecording(t.Context(), a, pr); err == nil {
		t.Fatal("pull-request preflight accepted missing repository factory")
	}
	if v, err := f.RecordSourceCommit(t.Context(), a, commit); err == nil || !reflect.DeepEqual(v, integrationdomain.SourceCommit{}) {
		t.Fatal("missing transaction returned commit", err)
	}
	if v, err := f.UpsertSourceBranch(t.Context(), a, branch); err == nil || !reflect.DeepEqual(v, integrationdomain.SourceBranch{}) {
		t.Fatal("missing transaction returned branch", err)
	}
	if v, err := f.RecordPullRequest(t.Context(), a, pr); err == nil || !reflect.DeepEqual(v, integrationdomain.PullRequest{}) {
		t.Fatal("missing transaction returned pull-request", err)
	}
}
