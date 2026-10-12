package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func TestMemorySourceWriteReadersKeepCurrentRepositoryAndHeadIdentitySeparateFromMetadata(t *testing.T) {
	tx, _, _ := memorySourceRepositoryReadFixture(t)
	r, ok := tx.Repositories().Source.(interface {
		integrationapp.SourceCommitReader
		integrationapp.SourceBranchReader
		integrationapp.PullRequestReader
	})
	if !ok {
		t.Fatal("memory source lacks focused commit/branch/pull-request readers")
	}
	repository := memorySourceRepositoryRecord("repository")
	repository.CloneURL = strings.Repeat("omitted", 100000)
	tx.state.SourceRepositories[repository.ID] = repository
	commit := domain.SourceCommit{ID: "commit", TenantID: "tenant", RepositoryID: repository.ID, SHA: strings.Repeat("a", 40), Author: strings.Repeat("a", 65536), MessageHash: sampleDigest("message"), CommittedAt: fixedNow(), CreatedAt: fixedNow(), SchemaVersion: domain.SourceCommitSchemaVersion}
	tx.state.SourceCommits[commit.ID] = commit
	identity, err := r.SourceCommitIdentityByID(t.Context(), "tenant", repository.ID, commit.ID)
	if err != nil || identity != (integrationapp.SourceCommitIdentity{ID: commit.ID, TenantID: "tenant", RepositoryID: repository.ID}) {
		t.Fatal("current head identity lost owned repository", err)
	}
	if _, err := r.SourceCommitIdentityByID(t.Context(), "tenant", "other", commit.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-repository head accepted", err)
	}
	if v, found, err := r.SourceCommitBySHA(t.Context(), "tenant", repository.ID, commit.SHA); err != nil || !found || v.Author != commit.Author || v.MessageHash != commit.MessageHash {
		t.Fatal("bounded commit read lost public fields", err)
	}
	commit.Author += "a"
	tx.state.SourceCommits[commit.ID] = commit
	if _, err := r.SourceCommitIdentityByID(t.Context(), "tenant", repository.ID, commit.ID); err != nil {
		t.Fatal("head identity read oversized author metadata", err)
	}
	if _, _, err := r.SourceCommitBySHA(t.Context(), "tenant", repository.ID, commit.SHA); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized selected commit accepted", err)
	}
	branch := domain.SourceBranch{ID: "branch", TenantID: "tenant", RepositoryID: repository.ID, Name: "main", HeadCommitID: commit.ID, Protected: true, ProtectionHash: "recorded", CreatedAt: fixedNow(), SchemaVersion: domain.SourceBranchSchemaVersion}
	tx.state.SourceBranches[branch.ID] = branch
	if v, found, err := r.SourceBranchByName(t.Context(), "tenant", repository.ID, "main"); err != nil || !found || v.ID != branch.ID || v.HeadCommitID != commit.ID || !v.Protected {
		t.Fatal("current branch read lost head or protection", err)
	}
	if provider, err := r.SourceRepositoryProvider(t.Context(), "tenant", repository.ID); err != nil || provider != repository.Provider {
		t.Fatal("provider-only read consulted clone URL", err)
	}
	var missing context.Context
	if _, _, err := r.SourceBranchByName(missing, "tenant", repository.ID, "main"); err == nil {
		t.Fatal("nil source read context accepted")
	}
}
