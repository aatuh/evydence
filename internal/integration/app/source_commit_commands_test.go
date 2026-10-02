package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceCommitFake struct {
	identity            SourceRepositoryIdentity
	commit              integrationdomain.SourceCommit
	audit               []application.AuditEvent
	failure             string
	transactions, reads int
	lookupSHA           string
}

func (f *sourceCommitFake) ExecuteSourceCommit(ctx context.Context, fn func(context.Context, SourceCommitTransaction) error) error {
	f.transactions++
	c := *f
	c.audit = append([]application.AuditEvent(nil), f.audit...)
	err := fn(ctx, &c)
	f.reads, f.lookupSHA = c.reads, c.lookupSHA
	if err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("injected commit failure")
	}
	f.commit, f.audit = c.commit, c.audit
	return nil
}
func (f *sourceCommitFake) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.failure == "scope" && r.ScopeOnly || f.failure == "grant" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *sourceCommitFake) LockSourceCommitRepository(context.Context, string, string) (SourceRepositoryIdentity, error) {
	if f.failure == "repository" {
		return SourceRepositoryIdentity{}, ErrNotFound
	}
	return f.identity, nil
}
func (f *sourceCommitFake) SourceCommitBySHA(_ context.Context, _, _, sha string) (integrationdomain.SourceCommit, bool, error) {
	f.reads++
	f.lookupSHA = sha
	if f.failure == "read" {
		return integrationdomain.SourceCommit{}, false, ErrConflict
	}
	return f.commit, f.commit.ID != "", nil
}
func (f *sourceCommitFake) InsertSourceCommit(_ context.Context, v integrationdomain.SourceCommit) error {
	if f.failure == "insert" {
		return errors.New("injected insert failure")
	}
	f.commit = v
	return nil
}
func (f *sourceCommitFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errors.New("injected audit failure")
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func sourceCommitFixture(t *testing.T) (*SourceCommitCommands, *sourceCommitFake, identitydomain.Actor, RecordSourceCommitInput) {
	t.Helper()
	f := &sourceCommitFake{identity: SourceRepositoryIdentity{ID: "repo", TenantID: "tenant", ProjectID: "project", ProductID: "product"}}
	c, err := NewSourceCommitCommands(SourceCommitConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, RecordSourceCommitInput{RepositoryID: " repo ", SHA: strings.Repeat("AB", 20), Author: " Original ", Message: " original message "}
}
func TestSourceCommitRecordingIsAtomicNormalizesSHAAndHashesExactBytes(t *testing.T) {
	c, f, a, in := sourceCommitFixture(t)
	v, err := c.RecordSourceCommit(t.Context(), a, in)
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(in.Message)))
	if err != nil || v.ID != "commit_id" || v.RepositoryID != "repo" || v.SHA != strings.ToLower(in.SHA) || v.Author != "Original" || v.MessageHash != hash || v.SchemaVersion != integrationdomain.SourceCommitSchemaVersion || v.CommittedAt != v.CreatedAt || v.CreatedAt.Nanosecond() != 123456000 || len(f.audit) != 1 {
		t.Fatal(v, f, err)
	}
	audit := f.audit[0]
	if audit.EntryType != "source_commit.recorded" || audit.SubjectType != "source_commit" || audit.SubjectID != v.ID || audit.ActorType != "api_key" || audit.ActorID != "key" {
		t.Fatal(audit)
	}
	in.SHA, in.Author, in.Message, in.CommittedAt = strings.ToLower(in.SHA), "changed", "changed", v.CommittedAt.Add(time.Hour)
	if again, err := c.RecordSourceCommit(t.Context(), a, in); err != nil || again != v || len(f.audit) != 1 || f.lookupSHA != v.SHA {
		t.Fatal("immutable reuse failed", again, err, f)
	}
	for _, message := range []string{"", " \t\n", "nul\x00inside"} {
		c, _, a, in := sourceCommitFixture(t)
		in.Message = message
		v, err := c.RecordSourceCommit(t.Context(), a, in)
		want := ""
		if strings.TrimSpace(message) != "" {
			want = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(message)))
		}
		if err != nil || v.MessageHash != want {
			t.Fatal(v, err)
		}
	}
}
func TestSourceCommitRecordingRollsBackEveryFailure(t *testing.T) {
	for _, failure := range []string{"scope", "repository", "grant", "read", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := sourceCommitFixture(t)
			f.failure = failure
			if v, err := c.RecordSourceCommit(t.Context(), a, in); err == nil || v.ID != "" || f.commit.ID != "" || len(f.audit) != 0 {
				t.Fatal(v, err, f)
			}
			if failure == "scope" && f.transactions != 0 {
				t.Fatal("scope denial entered transaction")
			}
		})
	}
}
func TestSourceCommitRecordingAuthorizesRepositoryBeforeMetadata(t *testing.T) {
	c, f, a, in := sourceCommitFixture(t)
	a.KeyID, a.UserID = "", "human"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other", Scopes: []string{"source:write"}}}
	if v, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" || f.reads != 0 {
		t.Fatal(v, err, f.reads)
	}
	a.ResourceGrants[0].ResourceID = "project"
	if _, err := c.RecordSourceCommit(t.Context(), a, in); err != nil || f.audit[0].ActorType != "human_user" {
		t.Fatal(err, f.audit)
	}
	a.ResourceGrants = nil
	if _, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.reads != 1 {
		t.Fatal("revoked grant read metadata", err, f.reads)
	}
	f.identity.TenantID = "other"
	if _, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant accepted", err)
	}
}
func TestSourceCommitRecordingRejectsInvalidInputsBeforeTransaction(t *testing.T) {
	for _, mutate := range []func(*RecordSourceCommitInput){
		func(in *RecordSourceCommitInput) { in.RepositoryID = "" }, func(in *RecordSourceCommitInput) { in.RepositoryID = strings.Repeat("x", 1025) },
		func(in *RecordSourceCommitInput) { in.SHA = "bad" }, func(in *RecordSourceCommitInput) { in.SHA = strings.Repeat("z", 40) }, func(in *RecordSourceCommitInput) { in.SHA = strings.Repeat("a", 64) },
		func(in *RecordSourceCommitInput) { in.Author = "bad\x00" }, func(in *RecordSourceCommitInput) { in.Author = string([]byte{0xff}) }, func(in *RecordSourceCommitInput) { in.Author = strings.Repeat("x", 65537) },
		func(in *RecordSourceCommitInput) { in.Message = strings.Repeat("x", 65537) }, func(in *RecordSourceCommitInput) { in.CommittedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		c, f, a, in := sourceCommitFixture(t)
		mutate(&in)
		if _, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f.transactions)
		}
	}
	c, f, a, in := sourceCommitFixture(t)
	//nolint:staticcheck // SA1012: deliberate invalid-context regression, not a production call.
	if _, err := c.RecordSourceCommit(nil, a, in); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.RecordSourceCommit(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	if _, err := NewSourceCommitCommands(SourceCommitConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
func TestSourceCommitRecordingRejectsCorruptExistingProjection(t *testing.T) {
	for _, mutate := range []func(*integrationdomain.SourceCommit){func(v *integrationdomain.SourceCommit) { v.TenantID = "other" }, func(v *integrationdomain.SourceCommit) { v.RepositoryID = "other" }, func(v *integrationdomain.SourceCommit) { v.SHA = "bad" }, func(v *integrationdomain.SourceCommit) { v.Author = strings.Repeat("x", 65537) }, func(v *integrationdomain.SourceCommit) { v.SchemaVersion = "unknown" }, func(v *integrationdomain.SourceCommit) { v.CommittedAt = time.Time{} }, func(v *integrationdomain.SourceCommit) { v.MessageHash = "raw text" }} {
		c, f, a, in := sourceCommitFixture(t)
		if _, err := c.RecordSourceCommit(t.Context(), a, in); err != nil {
			t.Fatal(err)
		}
		mutate(&f.commit)
		if v, err := c.RecordSourceCommit(t.Context(), a, in); !errors.Is(err, ErrConflict) || v.ID != "" || len(f.audit) != 1 {
			t.Fatal(v, err, f)
		}
	}
}
