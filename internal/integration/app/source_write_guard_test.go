package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSourceCatalogWritesBoundRawTextBeforeTrimming(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		for _, mutate := range []func(*RecordSourceCommitInput){func(in *RecordSourceCommitInput) { in.RepositoryID = strings.Repeat(" ", 1025) + "repo" }, func(in *RecordSourceCommitInput) { in.Author = strings.Repeat(" ", MaxSourceTextBytes+1) + "author" }, func(in *RecordSourceCommitInput) { in.SHA = strings.Repeat(" ", 1025) + strings.Repeat("a", 40) }} {
			c, f, a, in := sourceCommitFixture(t)
			mutate(&in)
			if v, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
				t.Fatal("raw commit padding reached transaction", v, err, f.transactions)
			}
		}
	})
	t.Run("branch", func(t *testing.T) {
		for _, mutate := range []func(*UpsertSourceBranchInput){func(in *UpsertSourceBranchInput) { in.RepositoryID = strings.Repeat(" ", 1025) + "repo" }, func(in *UpsertSourceBranchInput) { in.Name = strings.Repeat(" ", MaxSourceTextBytes+1) + "main" }, func(in *UpsertSourceBranchInput) { in.HeadCommitID = strings.Repeat(" ", 1025) + "commit" }, func(in *UpsertSourceBranchInput) {
			in.ProtectionHash = strings.Repeat(" ", MaxSourceTextBytes+1) + "hash"
		}} {
			c, f, a, in := sourceBranchFixture(t)
			mutate(&in)
			if v, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
				t.Fatal("raw branch padding reached transaction", v, err, f.transactions)
			}
		}
	})
	t.Run("pull-request", func(t *testing.T) {
		for _, mutate := range []func(*RecordPullRequestInput){func(in *RecordPullRequestInput) { in.RepositoryID = strings.Repeat(" ", 1025) + "repo" }, func(in *RecordPullRequestInput) { in.Title = strings.Repeat(" ", MaxSourceTextBytes+1) + "title" }, func(in *RecordPullRequestInput) { in.HeadCommitID = strings.Repeat(" ", 1025) + "head" }, func(in *RecordPullRequestInput) {
			in.ReviewDecision = strings.Repeat(" ", MaxSourceTextBytes+1) + "review"
		}, func(in *RecordPullRequestInput) { in.State = strings.Repeat(" ", MaxSourceTextBytes+1) + "open" }} {
			c, f, a, in := pullRequestFixture(t)
			mutate(&in)
			if v, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
				t.Fatal("raw PR padding reached transaction", v, err, f.transactions)
			}
		}
	})
}

func panicSourceClock() time.Time { panic("guard read clock") }
func panicSourceID(string) string { panic("guard allocated identity") }

func TestSourceCatalogReplayGuardsReadOnlyCurrentScope(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		c, f, a, in := sourceCommitFixture(t)
		guard, ok := any(c).(interface {
			AuthorizeSourceCommitRecording(context.Context, identitydomain.Actor, RecordSourceCommitInput) error
		})
		if !ok {
			t.Fatal("commit has no current replay guard")
		}
		c.config.Clock, c.config.IDs = application.ClockFunc(panicSourceClock), application.IDGeneratorFunc(panicSourceID)
		f.failure = "read"
		if err := guard.AuthorizeSourceCommitRecording(t.Context(), a, in); err != nil || f.reads != 0 || f.commit.ID != "" || len(f.audit) != 0 {
			t.Fatal("commit guard touched metadata or effects", err, f)
		}
		f.identity.TenantID = "other"
		if err := guard.AuthorizeSourceCommitRecording(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
			t.Fatal("guard accepted foreign repository", err)
		}
		f.identity.TenantID = "tenant"
		a.KeyID, a.UserID, a.ResourceGrants = "", "human", nil
		if err := guard.AuthorizeSourceCommitRecording(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.reads != 0 {
			t.Fatal("guard ignored current grants", err)
		}
	})
	t.Run("branch", func(t *testing.T) {
		c, f, a, in := sourceBranchFixture(t)
		guard, ok := any(c).(interface {
			AuthorizeSourceBranchUpsert(context.Context, identitydomain.Actor, UpsertSourceBranchInput) error
		})
		if !ok {
			t.Fatal("branch has no current replay guard")
		}
		c.config.Clock, c.config.IDs = application.ClockFunc(panicSourceClock), application.IDGeneratorFunc(panicSourceID)
		f.failure = "read"
		if err := guard.AuthorizeSourceBranchUpsert(t.Context(), a, in); err != nil || f.headReads != 1 || f.branchReads != 0 || f.inserts+f.updates != 0 || len(f.audit) != 0 {
			t.Fatal("branch guard touched mutable metadata or effects", err, f)
		}
		f.head.RepositoryID = "other"
		if err := guard.AuthorizeSourceBranchUpsert(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
			t.Fatal("guard accepted foreign head", err)
		}
		in.HeadCommitID = ""
		if err := guard.AuthorizeSourceBranchUpsert(t.Context(), a, in); err != nil || f.headReads != 2 || f.branchReads != 0 {
			t.Fatal("omitted head caused lookup", err, f)
		}
	})
	t.Run("pull-request", func(t *testing.T) {
		c, f, a, in := pullRequestFixture(t)
		guard, ok := any(c).(interface {
			AuthorizePullRequestRecording(context.Context, identitydomain.Actor, RecordPullRequestInput) error
		})
		if !ok {
			t.Fatal("PR has no current replay guard")
		}
		c.config.Clock, c.config.IDs = application.ClockFunc(panicSourceClock), application.IDGeneratorFunc(panicSourceID)
		f.failure = "provider"
		if err := guard.AuthorizePullRequestRecording(t.Context(), a, in); err != nil || f.headReads != 1 || f.providerReads != 0 || len(f.records)+len(f.audit) != 0 {
			t.Fatal("PR guard read provider metadata or wrote effects", err, f)
		}
		f.head.TenantID = "other"
		if err := guard.AuthorizePullRequestRecording(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
			t.Fatal("PR guard accepted foreign head", err)
		}
	})
}
