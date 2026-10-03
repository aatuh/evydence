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
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceCreationFake struct {
	project             SourceProjectIdentity
	identity            SourceRepositoryIdentity
	repository          integrationdomain.SourceRepository
	failure             string
	transactions, reads int
	audit               []application.AuditEvent
}

func (f *sourceCreationFake) ExecuteSourceRepository(ctx context.Context, fn func(context.Context, SourceRepositoryCreationTransaction) error) error {
	f.transactions++
	c := *f
	c.audit = append([]application.AuditEvent(nil), f.audit...)
	err := fn(ctx, &c)
	f.reads = c.reads
	if err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("commit failed")
	}
	f.repository, f.audit = c.repository, c.audit
	return nil
}
func (f *sourceCreationFake) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.failure == "scope" && r.ScopeOnly || f.failure == "grant" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *sourceCreationFake) LockRepositoryCreation(context.Context, string) error {
	if f.failure == "lock" {
		return ErrNotFound
	}
	return nil
}
func (f *sourceCreationFake) LockRepositoryProject(context.Context, string, string) (SourceProjectIdentity, error) {
	if f.failure == "project" {
		return SourceProjectIdentity{}, ErrNotFound
	}
	return f.project, nil
}
func (f *sourceCreationFake) RepositoryIdentityByName(context.Context, string, string, string) (SourceRepositoryIdentity, bool, error) {
	if f.failure == "identity" {
		return SourceRepositoryIdentity{}, false, errors.New("identity failed")
	}
	return f.identity, f.identity.ID != "", nil
}
func (f *sourceCreationFake) ReadSourceRepository(context.Context, string, string) (integrationdomain.SourceRepository, error) {
	f.reads++
	if f.failure == "read" {
		return integrationdomain.SourceRepository{}, ErrConflict
	}
	return f.repository, nil
}
func (f *sourceCreationFake) InsertSourceRepository(_ context.Context, v integrationdomain.SourceRepository) error {
	if f.failure == "insert" {
		return errors.New("insert failed")
	}
	f.repository = v
	return nil
}
func (f *sourceCreationFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errors.New("audit failed")
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func sourceCreationFixture(t *testing.T) (*SourceRepositoryCommands, *sourceCreationFake, identitydomain.Actor, CreateSourceRepositoryInput) {
	t.Helper()
	f := &sourceCreationFake{project: SourceProjectIdentity{ID: "project", TenantID: "tenant", ProductID: "product"}}
	c, err := NewSourceRepositoryCommands(SourceRepositoryCreationConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}, CreateSourceRepositoryInput{ProjectID: " project ", Provider: " github ", FullName: " org/api ", CloneURL: " https://example.test/org/api.git ", DefaultBranch: " main "}
}
func TestSourceRepositoryCreationCommitsAndPreservesOriginalMetadata(t *testing.T) {
	c, f, a, in := sourceCreationFixture(t)
	v, err := c.CreateSourceRepository(t.Context(), a, in)
	if err != nil || v.ID != "repo_id" || v.ProjectID != "project" || v.Provider != "github" || v.FullName != "org/api" || v.CloneURL != "https://example.test/org/api.git" || v.DefaultBranch != "main" || v.SchemaVersion != integrationdomain.SourceRepositorySchemaVersion || len(f.audit) != 1 || f.audit[0].EntryType != "source_repository.created" {
		t.Fatal(v, f, err)
	}
	f.identity = SourceRepositoryIdentity{ID: v.ID, TenantID: v.TenantID, ProjectID: v.ProjectID, ProductID: "product"}
	in.CloneURL = "changed"
	in.DefaultBranch = "changed"
	if again, err := c.CreateSourceRepository(t.Context(), a, in); err != nil || again != v || len(f.audit) != 1 {
		t.Fatal("existing repository mutated", again, err)
	}
}
func TestSourceRepositoryCreationAuthorizesExistingOwnerBeforeMetadataRead(t *testing.T) {
	c, f, a, in := sourceCreationFixture(t)
	a.KeyID = ""
	a.UserID = "human"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:write"}}}
	f.identity = SourceRepositoryIdentity{ID: "repo", TenantID: "tenant", ProjectID: "other", ProductID: "product"}
	if v, err := c.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" || f.reads != 0 {
		t.Fatal("existing metadata read before authorization", v, err, f.reads)
	}
	in.ProjectID = ""
	if _, err := c.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.reads != 0 {
		t.Fatal("scoped actor created detached repository", err)
	}
}
func TestSourceRepositoryCreationRollsBackAllFailuresAndRejectsForeignProject(t *testing.T) {
	for _, failure := range []string{"scope", "grant", "lock", "project", "identity", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := sourceCreationFixture(t)
			f.failure = failure
			v, err := c.CreateSourceRepository(t.Context(), a, in)
			if err == nil || v.ID != "" || f.repository.ID != "" || len(f.audit) != 0 {
				t.Fatal(v, f, err)
			}
			if failure == "scope" && f.transactions != 0 {
				t.Fatal("denied scope reached transaction")
			}
		})
	}
	c, f, a, in := sourceCreationFixture(t)
	f.project.TenantID = "other"
	if _, err := c.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
func TestSourceRepositoryCreationRejectsInvalidTextAndOversizedIndexKeys(t *testing.T) {
	for _, mutate := range []func(*CreateSourceRepositoryInput){func(in *CreateSourceRepositoryInput) { in.Provider = "" }, func(in *CreateSourceRepositoryInput) { in.ProjectID = "bad\x00" }, func(in *CreateSourceRepositoryInput) { in.FullName = strings.Repeat("n", 2305) }, func(in *CreateSourceRepositoryInput) { in.CloneURL = string([]byte{0xff}) }, func(in *CreateSourceRepositoryInput) { in.DefaultBranch = strings.Repeat("b", 65537) }} {
		c, f, a, in := sourceCreationFixture(t)
		mutate(&in)
		if _, err := c.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f.transactions)
		}
	}
}

func TestSourceRepositoryCreationRequiresDependenciesAndLiveContext(t *testing.T) {
	for _, mutate := range []func(*SourceRepositoryCreationConfig){func(c *SourceRepositoryCreationConfig) { c.Transactions = nil }, func(c *SourceRepositoryCreationConfig) { c.Authorizer = nil }, func(c *SourceRepositoryCreationConfig) { c.Clock = nil }, func(c *SourceRepositoryCreationConfig) { c.IDs = nil }} {
		c, _, _, _ := sourceCreationFixture(t)
		config := c.config
		mutate(&config)
		if _, err := NewSourceRepositoryCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	c, f, a, in := sourceCreationFixture(t)
	var missingContext context.Context
	if _, err := c.CreateSourceRepository(missingContext, a, in); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateSourceRepository(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
}

func TestSourceRepositoryCreationRejectsCorruptedExistingProjection(t *testing.T) {
	for _, failure := range []string{"read", "projection"} {
		c, f, a, in := sourceCreationFixture(t)
		f.identity = SourceRepositoryIdentity{ID: "existing", TenantID: "tenant", ProjectID: "project", ProductID: "product"}
		f.repository = integrationdomain.SourceRepository{ID: "existing", TenantID: "other", ProjectID: "project", Provider: "github", FullName: "org/api"}
		if failure == "read" {
			f.failure = "read"
		}
		if v, err := c.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, ErrConflict) || v.ID != "" || len(f.audit) != 0 {
			t.Fatal(v, err)
		}
	}
}
