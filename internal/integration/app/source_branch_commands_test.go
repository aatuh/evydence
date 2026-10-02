package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceBranchFake struct {
	sourceCommitFake
	branch                                   integrationdomain.SourceBranch
	head                                     SourceCommitIdentity
	branchReads, headReads, inserts, updates int
}

func (f *sourceBranchFake) ExecuteSourceBranch(ctx context.Context, fn func(context.Context, SourceBranchTransaction) error) error {
	f.transactions++
	c := *f
	c.audit = append([]application.AuditEvent(nil), f.audit...)
	err := fn(ctx, &c)
	f.branchReads, f.headReads = c.branchReads, c.headReads
	if err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("injected commit failure")
	}
	f.branch, f.audit, f.inserts, f.updates = c.branch, c.audit, c.inserts, c.updates
	return nil
}
func (f *sourceBranchFake) SourceCommitIdentityByID(context.Context, string, string, string) (SourceCommitIdentity, error) {
	f.headReads++
	if f.failure == "head" {
		return SourceCommitIdentity{}, ErrNotFound
	}
	return f.head, nil
}
func (f *sourceBranchFake) SourceBranchByName(context.Context, string, string, string) (integrationdomain.SourceBranch, bool, error) {
	f.branchReads++
	if f.failure == "read" {
		return integrationdomain.SourceBranch{}, false, ErrConflict
	}
	return f.branch, f.branch.ID != "", nil
}
func (f *sourceBranchFake) InsertSourceBranch(_ context.Context, v integrationdomain.SourceBranch) error {
	if f.failure == "insert" {
		return errors.New("injected insert failure")
	}
	f.branch = v
	f.inserts++
	return nil
}
func (f *sourceBranchFake) UpdateSourceBranch(_ context.Context, v integrationdomain.SourceBranch) error {
	if f.failure == "update" {
		return errors.New("injected update failure")
	}
	f.branch = v
	f.updates++
	return nil
}
func sourceBranchFixture(t *testing.T) (*SourceBranchCommands, *sourceBranchFake, identitydomain.Actor, UpsertSourceBranchInput) {
	t.Helper()
	f := &sourceBranchFake{sourceCommitFake: sourceCommitFake{identity: SourceRepositoryIdentity{ID: "repo", TenantID: "tenant", ProjectID: "project", ProductID: "product"}}, head: SourceCommitIdentity{ID: "commit", TenantID: "tenant", RepositoryID: "repo"}}
	c, err := NewSourceBranchCommands(SourceBranchConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, UpsertSourceBranchInput{RepositoryID: " repo ", Name: " main ", HeadCommitID: " commit ", Protected: true, ProtectionHash: " opaque snapshot hash "}
}
func TestSourceBranchUpsertPreservesIdentityAndAuditsCreationAndEveryUpdate(t *testing.T) {
	c, f, a, in := sourceBranchFixture(t)
	v, err := c.UpsertSourceBranch(t.Context(), a, in)
	if err != nil || v.ID != "branch_id" || v.RepositoryID != "repo" || v.Name != "main" || v.HeadCommitID != "commit" || !v.Protected || v.ProtectionHash != "opaque snapshot hash" || v.SchemaVersion != integrationdomain.SourceBranchSchemaVersion || v.CreatedAt.Nanosecond() != 123456000 || f.inserts != 1 || len(f.audit) != 1 || f.audit[0].EntryType != "source_branch.created" || f.audit[0].PayloadHash != v.ProtectionHash {
		t.Fatal(v, err, f)
	}
	in.HeadCommitID, in.ProtectionHash, in.Protected = "", "", false
	w, err := c.UpsertSourceBranch(t.Context(), a, in)
	if err != nil || w.ID != v.ID || w.CreatedAt != v.CreatedAt || w.HeadCommitID != "" || w.ProtectionHash != "" || w.Protected || f.updates != 1 || len(f.audit) != 2 || f.audit[1].EntryType != "source_branch.updated" || f.audit[1].SubjectID != v.ID {
		t.Fatal(w, err, f)
	}
	if again, err := c.UpsertSourceBranch(t.Context(), a, in); err != nil || again != w || len(f.audit) != 3 || f.updates != 2 {
		t.Fatal("unchanged new-key update omitted audit", again, err, f)
	}
}
func TestSourceBranchUpsertRollsBackCreateAndUpdateFailures(t *testing.T) {
	for _, update := range []bool{false, true} {
		for _, failure := range []string{"scope", "repository", "grant", "head", "read", "insert", "update", "audit", "commit"} {
			if update && failure == "insert" || !update && failure == "update" {
				continue
			}
			t.Run(failure+map[bool]string{false: "-create", true: "-update"}[update], func(t *testing.T) {
				c, f, a, in := sourceBranchFixture(t)
				if update {
					if _, err := c.UpsertSourceBranch(t.Context(), a, in); err != nil {
						t.Fatal(err)
					}
				}
				original, audits := f.branch, len(f.audit)
				f.failure = failure
				in.ProtectionHash = "changed"
				if v, err := c.UpsertSourceBranch(t.Context(), a, in); err == nil || v.ID != "" || f.branch != original || len(f.audit) != audits {
					t.Fatal(v, err, f)
				}
			})
		}
	}
}
func TestSourceBranchUpsertAuthorizesBeforePrivateReadsAndRejectsForeignHeads(t *testing.T) {
	c, f, a, in := sourceBranchFixture(t)
	a.KeyID, a.UserID = "", "human"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other", Scopes: []string{"source:write"}}}
	if v, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" || f.headReads != 0 || f.branchReads != 0 {
		t.Fatal(v, err, f)
	}
	a.ResourceGrants[0].ResourceID = "project"
	if _, err := c.UpsertSourceBranch(t.Context(), a, in); err != nil || f.audit[0].ActorType != "human_user" {
		t.Fatal(err, f.audit)
	}
	a.ResourceGrants = nil
	if _, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.branchReads != 1 || f.headReads != 1 {
		t.Fatal("removed grant retained access", err, f)
	}
	for _, head := range []SourceCommitIdentity{{ID: "commit", TenantID: "other", RepositoryID: "repo"}, {ID: "commit", TenantID: "tenant", RepositoryID: "other"}, {ID: "other", TenantID: "tenant", RepositoryID: "repo"}} {
		c, f, a, in := sourceBranchFixture(t)
		f.head = head
		if _, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, ErrNotFound) || f.branchReads != 0 || f.branch.ID != "" {
			t.Fatal("foreign head accepted", err, f)
		}
	}
	c, f, a, in = sourceBranchFixture(t)
	f.identity.TenantID = "other"
	if _, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
func TestSourceBranchUpsertRejectsInvalidInputAndCorruptStoredIdentity(t *testing.T) {
	for _, mutate := range []func(*UpsertSourceBranchInput){func(in *UpsertSourceBranchInput) { in.Name = " " }, func(in *UpsertSourceBranchInput) { in.RepositoryID = strings.Repeat("x", 1025) }, func(in *UpsertSourceBranchInput) { in.Name = strings.Repeat("n", 2305) }, func(in *UpsertSourceBranchInput) { in.Name = "bad\x00" }, func(in *UpsertSourceBranchInput) { in.Name = string([]byte{0xff}) }, func(in *UpsertSourceBranchInput) { in.HeadCommitID = strings.Repeat("h", 1025) }, func(in *UpsertSourceBranchInput) { in.ProtectionHash = strings.Repeat("h", 65537) }} {
		c, f, a, in := sourceBranchFixture(t)
		mutate(&in)
		if _, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f.transactions)
		}
	}
	for _, mutate := range []func(*integrationdomain.SourceBranch){func(v *integrationdomain.SourceBranch) { v.TenantID = "other" }, func(v *integrationdomain.SourceBranch) { v.RepositoryID = "other" }, func(v *integrationdomain.SourceBranch) { v.Name = "other" }, func(v *integrationdomain.SourceBranch) { v.ProtectionHash = strings.Repeat("x", 65537) }, func(v *integrationdomain.SourceBranch) { v.SchemaVersion = "unknown" }, func(v *integrationdomain.SourceBranch) { v.CreatedAt = time.Time{} }} {
		c, f, a, in := sourceBranchFixture(t)
		if _, err := c.UpsertSourceBranch(t.Context(), a, in); err != nil {
			t.Fatal(err)
		}
		mutate(&f.branch)
		if v, err := c.UpsertSourceBranch(t.Context(), a, in); !errors.Is(err, ErrConflict) || v.ID != "" || len(f.audit) != 1 {
			t.Fatal(v, err, f)
		}
	}
	c, f, a, in := sourceBranchFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.UpsertSourceBranch(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	if _, err := NewSourceBranchCommands(SourceBranchConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
