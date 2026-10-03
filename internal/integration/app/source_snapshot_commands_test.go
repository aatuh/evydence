package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceSnapshotFake struct {
	failure         string
	transactions    int
	stages          []string
	repositoryInput CreateSourceRepositoryInput
	commitInput     RecordSourceCommitInput
	branchInput     UpsertSourceBranchInput
	prInput         RecordPullRequestInput
}

func (f *sourceSnapshotFake) ExecuteSourceSnapshot(ctx context.Context, fn func(context.Context, SourceSnapshotTransaction) error) error {
	f.transactions++
	c := *f
	c.stages = append([]string(nil), f.stages...)
	if err := fn(ctx, &c); err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("injected transaction failure")
	}
	f.stages, f.repositoryInput, f.commitInput, f.branchInput, f.prInput = c.stages, c.repositoryInput, c.commitInput, c.branchInput, c.prInput
	return nil
}
func (f *sourceSnapshotFake) stage(stage string) error {
	if f.failure == stage {
		return ErrValidation
	}
	f.stages = append(f.stages, stage)
	return nil
}
func (f *sourceSnapshotFake) CreateSourceRepository(_ context.Context, a identitydomain.Actor, in CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	f.repositoryInput = in
	return integrationdomain.SourceRepository{ID: "actual_repo", TenantID: a.TenantID, Provider: in.Provider}, f.stage("repository")
}
func (f *sourceSnapshotFake) RecordSourceCommit(_ context.Context, a identitydomain.Actor, in RecordSourceCommitInput) (integrationdomain.SourceCommit, error) {
	f.commitInput = in
	return integrationdomain.SourceCommit{ID: "actual_commit", TenantID: a.TenantID, RepositoryID: in.RepositoryID}, f.stage("source_commit")
}
func (f *sourceSnapshotFake) UpsertSourceBranch(_ context.Context, a identitydomain.Actor, in UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	f.branchInput = in
	return integrationdomain.SourceBranch{ID: "actual_branch", TenantID: a.TenantID, RepositoryID: in.RepositoryID, HeadCommitID: in.HeadCommitID}, f.stage("branch")
}
func (f *sourceSnapshotFake) RecordPullRequest(_ context.Context, a identitydomain.Actor, in RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	f.prInput = in
	return integrationdomain.PullRequest{ID: "actual_pr", TenantID: a.TenantID, RepositoryID: in.RepositoryID, HeadCommitID: in.HeadCommitID}, f.stage("pull_request")
}
func sourceSnapshotFixture(t *testing.T) (*SourceSnapshotCommands, *sourceSnapshotFake, identitydomain.Actor, SourceSnapshotInput) {
	t.Helper()
	f := &sourceSnapshotFake{}
	c, err := NewSourceSnapshotCommands(SourceSnapshotConfig{Transactions: f, Authorizer: integrationquery.NewSourceWriteAuthorizer()})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, SourceSnapshotInput{ProjectID: "project", Repository: SourceSnapshotRepositoryInput{FullName: "org/api", CloneURL: "opaque", DefaultBranch: "main"}, Commit: &SourceSnapshotCommitInput{SHA: "input-sha", Message: " private message "}, Branch: &SourceSnapshotBranchInput{Name: "main", Protected: true, ProtectionHash: "opaque"}, PullRequest: &SourceSnapshotPullRequestInput{ProviderID: "17", Title: "Change", State: "merged"}}
}
func TestSourceSnapshotCommandBindsActualRepositoryAndCommitInOneTransaction(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		c, f, a, in := sourceSnapshotFixture(t)
		v, err := c.RecordSourceSnapshot(t.Context(), a, provider, in)
		if err != nil || f.transactions != 1 || !slices.Equal(f.stages, []string{"repository", "source_commit", "branch", "pull_request"}) || v.Repository.ID != "actual_repo" || v.Commit.ID != "actual_commit" || v.Branch.HeadCommitID != v.Commit.ID || v.PullRequest.HeadCommitID != v.Commit.ID {
			t.Fatal(v, err, f)
		}
		if f.repositoryInput.ProjectID != "project" || f.repositoryInput.Provider != provider || f.commitInput.RepositoryID != v.Repository.ID || f.commitInput.Message != in.Commit.Message || f.branchInput.RepositoryID != v.Repository.ID || f.prInput.RepositoryID != v.Repository.ID || f.prInput.Provider != provider {
			t.Fatal("snapshot relationships not server-bound", f)
		}
	}
	c, f, a, in := sourceSnapshotFixture(t)
	in.Commit = nil
	v, err := c.RecordSourceSnapshot(t.Context(), a, "github", in)
	if err != nil || v.Commit.ID != "" || f.branchInput.HeadCommitID != "" || f.prInput.HeadCommitID != "" || len(f.stages) != 3 {
		t.Fatal(v, err, f)
	}
	c, f, a, in = sourceSnapshotFixture(t)
	in.Commit, in.Branch, in.PullRequest = nil, nil, nil
	v, err = c.RecordSourceSnapshot(t.Context(), a, "gitlab", in)
	if err != nil || v.Commit.ID != "" || v.Branch.ID != "" || v.PullRequest.ID != "" || len(f.stages) != 1 {
		t.Fatal(v, err, f)
	}
}
func TestSourceSnapshotCommandRollsBackEveryStageAndRejectsMissingScope(t *testing.T) {
	for _, failure := range []string{"repository", "source_commit", "branch", "pull_request", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := sourceSnapshotFixture(t)
			f.failure = failure
			if v, err := c.RecordSourceSnapshot(t.Context(), a, "github", in); err == nil || v != (SourceSnapshotResult{}) || len(f.stages) != 0 {
				t.Fatal(v, err, f)
			}
		})
	}
	c, f, a, in := sourceSnapshotFixture(t)
	a.Scopes = nil
	if _, err := c.RecordSourceSnapshot(t.Context(), a, "github", in); !errors.Is(err, application.ErrForbidden) || f.transactions != 0 {
		t.Fatal(err, f)
	}
	a.Scopes = []string{"source:write"}
	if _, err := c.RecordSourceSnapshot(t.Context(), a, "untrusted-provider", in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
		t.Fatal(err, f)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.RecordSourceSnapshot(ctx, a, "github", in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err, f)
	}
	if _, err := NewSourceSnapshotCommands(SourceSnapshotConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
