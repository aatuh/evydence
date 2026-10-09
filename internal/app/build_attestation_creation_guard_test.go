package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLocalBuildAttestationGuardChecksCurrentOwnershipAndGrantsWithoutIngestion(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	p, err := l.CreateProduct(t.Context(), a, "Attestation", "attestation")
	if err != nil {
		t.Fatal(err)
	}
	j, err := l.CreateProject(t.Context(), a, p.ID, "Attestation")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := l.RegisterArtifact(t.Context(), a, "Artifact", "application/octet-stream", sampleDigest("guard"), 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.CreateBuildRun(t.Context(), a, CreateBuildRunInput{ProjectID: j.ID, ReleaseID: r.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("attestation guard used clock") }
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeBuildWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: j.ID, Scopes: []string{ScopeBuildWrite}}}}
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), human, b.ID); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = nil
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), human, b.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained replay", err)
	}
	changed := b
	changed.Repository = strings.Repeat("private-", 100000)
	changed.SourceIdentity = map[string]any{"private": strings.Repeat("x", 100000)}
	l.buildRuns[b.ID] = changed
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); err != nil {
		t.Fatal("guard materialized private build metadata", err)
	}
	foreignArtifact := artifact
	foreignArtifact.TenantID = "other"
	l.artifacts[artifact.ID] = foreignArtifact
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign output retained replay", err)
	}
	l.artifacts[artifact.ID] = artifact
	foreignProduct := p
	foreignProduct.TenantID = "other"
	l.products[p.ID] = foreignProduct
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product retained replay", err)
	}
	l.products[p.ID] = p
	changed.ReleaseID = "missing"
	l.buildRuns[b.ID] = changed
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing release retained replay", err)
	}
	changed = b
	changed.Outputs = []domain.BuildOutput{{ArtifactID: strings.Repeat(" ", 1025)}}
	l.buildRuns[b.ID] = changed
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized stored output ID escaped guard", err)
	}
	l.buildRuns[b.ID] = b
	delete(l.tenants, a.TenantID)
	if err := l.AuthorizeBuildAttestationCreation(t.Context(), a, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant retained replay", err)
	}
	if len(l.attestations) != 0 || len(l.chain[a.TenantID]) != audits {
		t.Fatal("guard wrote ingestion effects")
	}
}
