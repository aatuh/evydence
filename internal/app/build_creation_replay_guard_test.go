package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestLocalBuildCreationGuardChecksCurrentParentsOutputsAndGrants(t *testing.T) {
	l := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Build", "build")
	if err != nil {
		t.Fatal(err)
	}
	project, err := l.CreateProject(t.Context(), a, p.ID, "Build")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	artifact, err := l.RegisterArtifact(t.Context(), a, "Artifact", "application/octet-stream", digest, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := releaseapp.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: r.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: fixedNow(), Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}}}
	_, err = l.CreateBuildRun(t.Context(), a, CreateBuildRunInput{ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Provider: in.Provider, CommitSHA: in.CommitSHA, Status: in.Status, StartedAt: in.StartedAt, Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("read-only build guard used clock") }
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeBuildWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{ScopeBuildWrite}}}}
	if err := l.AuthorizeBuildCreation(t.Context(), human, in); err != nil {
		t.Fatal("current project/output grant denied", err)
	}
	human.ResourceGrants = nil
	if err := l.AuthorizeBuildCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained build replay", err)
	}
	// Historical replay guards inspect ownership, not mutable digest metadata.
	changed := artifact
	changed.Digest = "not-a-current-digest"
	l.artifacts[artifact.ID] = changed
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); err != nil {
		t.Fatal("replay guard reverified historical digest", err)
	}
	changed.TenantID = "other"
	l.artifacts[artifact.ID] = changed
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign output retained build replay", err)
	}
	l.artifacts[artifact.ID] = artifact
	foreignProduct := p
	foreignProduct.TenantID = "other"
	l.products[p.ID] = foreignProduct
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product retained build replay", err)
	}
	l.products[p.ID] = p
	foreignProject := project
	foreignProject.TenantID = "other"
	l.projects[project.ID] = foreignProject
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign project retained build replay", err)
	}
	l.projects[project.ID] = project
	foreignRelease := r
	foreignRelease.TenantID = "other"
	l.releases[r.ID] = foreignRelease
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign release retained build replay", err)
	}
	l.releases[r.ID] = r
	delete(l.tenants, a.TenantID)
	if err := l.AuthorizeBuildCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant retained build replay", err)
	}
	if len(l.buildRuns) != 1 || len(l.chain[a.TenantID]) != audits {
		t.Fatal("read-only guard wrote a build or audit")
	}
}
