package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildGuardFake struct {
	parents                                   BuildCreationCoordinates
	artifact                                  releasedomain.Artifact
	scopeReads, artifactReads, authorizations int
	denied                                    bool
	err                                       error
}

func (f *buildGuardFake) ExecuteBuild(ctx context.Context, fn func(context.Context, BuildTransaction) error) error {
	return fn(ctx, f)
}
func (f *buildGuardFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.authorizations++
	if f.denied && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *buildGuardFake) ReadBuildCreationScope(context.Context, string, string, string) (BuildCreationCoordinates, error) {
	f.scopeReads++
	return f.parents, f.err
}
func (f *buildGuardFake) ReadBuildCreationArtifact(context.Context, string, string) (releasedomain.Artifact, error) {
	f.artifactReads++
	return f.artifact, f.err
}
func (*buildGuardFake) GetProject(context.Context, string, string) (releasedomain.Project, error) {
	panic("guard read project metadata")
}
func (*buildGuardFake) GetRelease(context.Context, string, string) (releasedomain.Release, error) {
	panic("guard read release version")
}
func (*buildGuardFake) GetArtifact(context.Context, string, string) (releasedomain.Artifact, error) {
	panic("guard read digest metadata")
}
func (*buildGuardFake) InsertBuildRun(context.Context, releasedomain.BuildRun) error {
	panic("guard inserted build")
}
func (*buildGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard appended audit")
}

func TestBuildCreationGuardNeverReadsMetadataOrWritesAndDeduplicatesArtifacts(t *testing.T) {
	f := newServiceFixture(t)
	tx := &buildGuardFake{parents: BuildCreationCoordinates{TenantID: "tenant", ProjectID: "project", ProductID: "product", ReleaseID: "release", ReleaseProductID: "product"}, artifact: releasedomain.Artifact{ID: "artifact", TenantID: "tenant"}}
	s, err := NewBuildCommands(BuildCommandConfig{Reader: f.reader, Authorizer: f.authorizer, Transactions: tx, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeBuildWrite}}
	in := CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: testSHA256('a')}, {ArtifactID: "artifact", Digest: testSHA256('a')}}}
	if err := s.AuthorizeBuildCreation(t.Context(), a, in); err != nil || tx.scopeReads != 1 || tx.artifactReads != 1 || tx.authorizations != 3 {
		t.Fatal("build guard skipped or repeated coordinate checks", err, tx)
	}
	tx.denied = true
	before := tx.artifactReads
	if err := s.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || tx.artifactReads != before {
		t.Fatal("denied parent reached artifacts", err, tx)
	}
	tx.denied = false
	tx.parents.ReleaseProductID = "other"
	if err := s.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("guard accepted product mismatch", err)
	}
	tx.parents.ReleaseProductID = "product"
	tx.artifact.TenantID = "other"
	if err := s.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("guard accepted foreign output artifact", err)
	}
	tx.parents.TenantID = "other"
	if err := s.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("guard accepted foreign parent scope", err)
	}
}
