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

type pullRequestFake struct {
	sourceCommitFake
	head                     SourceCommitIdentity
	provider                 string
	records                  []integrationdomain.PullRequest
	headReads, providerReads int
}

func (f *pullRequestFake) ExecutePullRequest(ctx context.Context, fn func(context.Context, PullRequestTransaction) error) error {
	f.transactions++
	c := *f
	c.audit = append([]application.AuditEvent(nil), f.audit...)
	c.records = append([]integrationdomain.PullRequest(nil), f.records...)
	err := fn(ctx, &c)
	f.headReads, f.providerReads = c.headReads, c.providerReads
	if err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("injected commit failure")
	}
	f.audit, f.records = c.audit, c.records
	return nil
}
func (f *pullRequestFake) SourceCommitIdentityByID(context.Context, string, string, string) (SourceCommitIdentity, error) {
	f.headReads++
	if f.failure == "head" {
		return SourceCommitIdentity{}, ErrNotFound
	}
	return f.head, nil
}
func (f *pullRequestFake) SourceRepositoryProvider(context.Context, string, string) (string, error) {
	f.providerReads++
	if f.failure == "provider" {
		return "", ErrConflict
	}
	return f.provider, nil
}
func (f *pullRequestFake) InsertPullRequest(_ context.Context, v integrationdomain.PullRequest) error {
	if f.failure == "insert" {
		return errors.New("injected insert failure")
	}
	f.records = append(f.records, v)
	return nil
}
func pullRequestFixture(t *testing.T) (*PullRequestCommands, *pullRequestFake, identitydomain.Actor, RecordPullRequestInput) {
	t.Helper()
	f := &pullRequestFake{sourceCommitFake: sourceCommitFake{identity: SourceRepositoryIdentity{ID: "repo", TenantID: "tenant", ProjectID: "project", ProductID: "product"}}, head: SourceCommitIdentity{ID: "head", TenantID: "tenant", RepositoryID: "repo"}, provider: "github"}
	ids := 0
	c, err := NewPullRequestCommands(PullRequestConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { ids++; return p + strings.Repeat("x", ids) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, RecordPullRequestInput{RepositoryID: " repo ", ProviderID: " 17 ", Title: " Change ", State: " open ", SourceBranch: " feature ", TargetBranch: " main ", HeadCommitID: " head ", ReviewDecision: " arbitrary recorded decision "}
}
func TestPullRequestRecordingDefaultsProviderAndAppendsSnapshots(t *testing.T) {
	c, f, a, in := pullRequestFixture(t)
	v, err := c.RecordPullRequest(t.Context(), a, in)
	if err != nil || v.ID == "" || v.Provider != "github" || v.ProviderID != "17" || v.Title != "Change" || v.State != "open" || v.SourceBranch != "feature" || v.TargetBranch != "main" || v.HeadCommitID != "head" || v.ReviewDecision != "arbitrary recorded decision" || v.SchemaVersion != integrationdomain.PullRequestSchemaVersion || v.CreatedAt.Nanosecond() != 123456000 || len(f.records) != 1 || len(f.audit) != 1 {
		t.Fatal(v, err, f)
	}
	audit := f.audit[0]
	if audit.EntryType != "pull_request.recorded" || audit.SubjectType != "pull_request" || audit.SubjectID != v.ID || audit.ActorType != "api_key" || audit.ActorID != "key" || audit.PayloadHash != "" || audit.SignatureRef != "" {
		t.Fatal(audit)
	}
	in.Title, in.State = "Changed", "merged"
	w, err := c.RecordPullRequest(t.Context(), a, in)
	if err != nil || w.ID == v.ID || len(f.records) != 2 || f.records[0] != v || w.State != "merged" || len(f.audit) != 2 {
		t.Fatal("new snapshot overwrote historical record", w, err, f)
	}
	in.Provider = " gitlab "
	in.HeadCommitID = ""
	w, err = c.RecordPullRequest(t.Context(), a, in)
	if err != nil || w.Provider != "gitlab" || w.HeadCommitID != "" || f.providerReads != 2 || f.headReads != 2 {
		t.Fatal("explicit provider did not bypass fallback read", w, err, f)
	}
}
func TestPullRequestRecordingRollsBackEveryFailure(t *testing.T) {
	for _, failure := range []string{"scope", "repository", "grant", "head", "provider", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := pullRequestFixture(t)
			f.failure = failure
			if v, err := c.RecordPullRequest(t.Context(), a, in); err == nil || v.ID != "" || len(f.records) != 0 || len(f.audit) != 0 {
				t.Fatal(v, err, f)
			}
			if failure == "scope" && f.transactions != 0 {
				t.Fatal("denied scope reached transaction")
			}
		})
	}
}
func TestPullRequestRecordingAuthorizesBeforeMetadataAndRejectsForeignHeads(t *testing.T) {
	c, f, a, in := pullRequestFixture(t)
	a.KeyID, a.UserID = "", "human"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other", Scopes: []string{"source:write"}}}
	if v, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" || f.headReads != 0 || f.providerReads != 0 {
		t.Fatal(v, err, f)
	}
	a.ResourceGrants[0].ResourceID = "project"
	if _, err := c.RecordPullRequest(t.Context(), a, in); err != nil || f.audit[0].ActorType != "human_user" {
		t.Fatal(err, f.audit)
	}
	a.ResourceGrants = nil
	if _, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.providerReads != 1 || f.headReads != 1 {
		t.Fatal("removed grant retained metadata access", err, f)
	}
	for _, head := range []SourceCommitIdentity{{ID: "head", TenantID: "other", RepositoryID: "repo"}, {ID: "head", TenantID: "tenant", RepositoryID: "other"}, {ID: "wrong", TenantID: "tenant", RepositoryID: "repo"}} {
		c, f, a, in := pullRequestFixture(t)
		f.head = head
		if _, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, ErrNotFound) || f.providerReads != 0 {
			t.Fatal("foreign head accepted", err, f)
		}
	}
	c, f, a, in = pullRequestFixture(t)
	f.identity.TenantID = "other"
	if _, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
func TestPullRequestRecordingBoundsInputsAndStoredProvider(t *testing.T) {
	for _, mutate := range []func(*RecordPullRequestInput){func(in *RecordPullRequestInput) { in.RepositoryID = "" }, func(in *RecordPullRequestInput) { in.RepositoryID = strings.Repeat("r", 1025) }, func(in *RecordPullRequestInput) { in.ProviderID = " " }, func(in *RecordPullRequestInput) { in.Title = " " }, func(in *RecordPullRequestInput) { in.Title = strings.Repeat("x", 65537) }, func(in *RecordPullRequestInput) { in.Provider = "bad\x00" }, func(in *RecordPullRequestInput) { in.ReviewDecision = string([]byte{0xff}) }, func(in *RecordPullRequestInput) { in.SourceBranch = strings.Repeat("x", 65537) }, func(in *RecordPullRequestInput) { in.HeadCommitID = strings.Repeat("x", 1025) }, func(in *RecordPullRequestInput) { in.State = "OPEN" }} {
		c, f, a, in := pullRequestFixture(t)
		mutate(&in)
		if _, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f.transactions)
		}
	}
	for _, provider := range []string{"", strings.Repeat("x", 65537), "bad\x00"} {
		c, f, a, in := pullRequestFixture(t)
		f.provider = provider
		if v, err := c.RecordPullRequest(t.Context(), a, in); !errors.Is(err, ErrConflict) || v.ID != "" || len(f.records) != 0 {
			t.Fatal(v, err)
		}
	}
	c, f, a, in := pullRequestFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.RecordPullRequest(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	if _, err := NewPullRequestCommands(PullRequestConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
