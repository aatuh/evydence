package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestLocalArtifactImageRegistrationGuardsUseCurrentOwnershipAndGrantsWithoutWrites(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Parent", "parent")
	if err != nil {
		t.Fatal(err)
	}
	j, err := l.CreateProject(t.Context(), a, p.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	artifact, err := l.RegisterArtifact(t.Context(), a, "Artifact", "text/plain", digest, 1)
	if err != nil {
		t.Fatal(err)
	}
	image, err := l.RegisterContainerImage(t.Context(), a, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api", Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.CreateBuildRun(t.Context(), a, CreateBuildRunInput{ProjectID: j.ID, ReleaseID: r.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("b", 40), Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}}}); err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("local guard used clock") }
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: j.ID, Scopes: []string{ScopeEvidenceWrite}}}}
	in := releaseapp.RegisterArtifactInput{Name: "Artifact", MediaType: "text/plain", Digest: digest, Size: 1}
	imageIn := releaseapp.RegisterContainerImageInput{Repository: image.Repository, Digest: digest} // Existing attachment cannot be bypassed by omission.
	checks := []func(domain.Actor) error{func(a domain.Actor) error { return l.AuthorizeArtifactRegistration(t.Context(), a, in) }, func(a domain.Actor) error { return l.AuthorizeContainerImageRegistration(t.Context(), a, imageIn) }}
	for _, check := range checks {
		if err := check(human); err != nil {
			t.Fatal("current grant denied", err)
		}
	}
	human.ResourceGrants = nil
	for _, check := range checks {
		if err := check(human); !errors.Is(err, ErrForbidden) {
			t.Fatal("removed grant retained replay", err)
		}
	}
	changed := artifact
	changed.Name = strings.Repeat("private-", 10000)
	changed.MediaType = changed.Name
	l.artifacts[artifact.ID] = changed
	for _, check := range checks {
		if err := check(a); err != nil {
			t.Fatal("guard reread metadata", err)
		}
	}
	changed.TenantID = "foreign"
	l.artifacts[artifact.ID] = changed
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign existing image attachment retained replay", err)
	}
	l.artifacts[artifact.ID] = artifact
	imageIn.ArtifactID = "missing"
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing submitted attachment retained replay", err)
	}
	imageIn.ArtifactID = ""
	delete(l.tenants, a.TenantID)
	for _, check := range checks {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing tenant retained replay", err)
		}
	}
	if len(l.artifacts) != 1 || len(l.images) != 1 || len(l.chain[a.TenantID]) != audits {
		t.Fatal("guard changed artifact/image/audit state")
	}
}
