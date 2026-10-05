package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLocalSourceWriteGuardsCheckCurrentParentsAndGrants(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Source", "source")
	if err != nil {
		t.Fatal(err)
	}
	project, err := l.CreateProject(t.Context(), a, p.ID, "Source")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := l.CreateSourceRepository(t.Context(), a, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "org/api"})
	if err != nil {
		t.Fatal(err)
	}
	head, err := l.RecordSourceCommit(t.Context(), a, RecordCommitInput{RepositoryID: repo.ID, SHA: strings.Repeat("a", 40)})
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := any(l).(interface {
		AuthorizeSourceCommitRecording(context.Context, domain.Actor, RecordCommitInput) error
		AuthorizeSourceBranchUpsert(context.Context, domain.Actor, UpsertBranchInput) error
		AuthorizePullRequestRecording(context.Context, domain.Actor, RecordPullRequestInput) error
	})
	if !ok {
		t.Fatal("local source writes lack current replay guards")
	}
	checks := []func(domain.Actor) error{
		func(a domain.Actor) error {
			return guard.AuthorizeSourceCommitRecording(t.Context(), a, RecordCommitInput{RepositoryID: repo.ID, SHA: strings.Repeat("a", 40)})
		},
		func(a domain.Actor) error {
			return guard.AuthorizeSourceBranchUpsert(t.Context(), a, UpsertBranchInput{RepositoryID: repo.ID, Name: "main", HeadCommitID: head.ID})
		},
		func(a domain.Actor) error {
			return guard.AuthorizePullRequestRecording(t.Context(), a, RecordPullRequestInput{RepositoryID: repo.ID, ProviderID: "17", Title: "Change", State: "open", HeadCommitID: head.ID})
		},
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeSourceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{ScopeSourceWrite}}}}
	for _, check := range checks {
		if err := check(human); err != nil {
			t.Fatal(err)
		}
	}
	human.ResourceGrants = nil
	for _, check := range checks {
		if err := check(human); !errors.Is(err, ErrForbidden) {
			t.Fatal("removed grants retained replay access", err)
		}
	}
	product := l.products[p.ID]
	product.TenantID = "other"
	l.products[p.ID] = product
	for _, check := range checks {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign product retained replay access", err)
		}
	}
	product.TenantID = a.TenantID
	l.products[p.ID] = product
	commit := l.commits[head.ID]
	commit.RepositoryID = "other"
	l.commits[head.ID] = commit
	for _, check := range checks[1:] {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign head retained replay access", err)
		}
	}
	delete(l.tenants, a.TenantID)
	for _, check := range checks {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing tenant retained replay access", err)
		}
	}
}

func TestLocalSourceWritesRejectRawPaddingBeforeLookup(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	repository := strings.Repeat(" ", 1025) + "repo"
	if _, err := l.RecordSourceCommit(t.Context(), a, RecordCommitInput{RepositoryID: repository, SHA: strings.Repeat("a", 40)}); !errors.Is(err, ErrValidation) {
		t.Fatal("commit raw bound bypassed", err)
	}
	if _, err := l.UpsertSourceBranch(t.Context(), a, UpsertBranchInput{RepositoryID: repository, Name: "main"}); !errors.Is(err, ErrValidation) {
		t.Fatal("branch raw bound bypassed", err)
	}
	if _, err := l.RecordPullRequest(t.Context(), a, RecordPullRequestInput{RepositoryID: repository, ProviderID: "17", Title: "Change", State: "open"}); !errors.Is(err, ErrValidation) {
		t.Fatal("PR raw bound bypassed", err)
	}
}
