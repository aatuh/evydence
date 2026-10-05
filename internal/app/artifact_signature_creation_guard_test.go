package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestLocalArtifactSignatureCreationGuardIsReadOnlyAndCurrent(t *testing.T) {
	l := NewLedger(Config{})
	a, release, _ := setupReleaseRiskFixture(t, l)
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID, Digest: "sha256:opaque"}
	l.projects["project"] = domain.Project{ID: "project", TenantID: a.TenantID, ProductID: release.ProductID}
	l.buildRuns["build"] = domain.BuildRun{ID: "build", TenantID: a.TenantID, ProjectID: "project", ReleaseID: release.ID, Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:opaque"}}}
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "cosign", Signature: "recorded"}
	l.now = func() time.Time { panic("local guard used clock") }
	before := len(l.chain[a.TenantID])
	for _, grant := range []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeEvidenceWrite}}, {ResourceType: "product", ResourceID: release.ProductID, Scopes: []string{ScopeEvidenceWrite}}, {ResourceType: "project", ResourceID: "project", Scopes: []string{ScopeEvidenceWrite}}, {ResourceType: "release", ResourceID: release.ID, Scopes: []string{ScopeEvidenceWrite}}} {
		human := domain.Actor{TenantID: a.TenantID, UserID: "user", Scopes: []string{ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{grant}}
		if err := l.AuthorizeArtifactSignatureCreation(t.Context(), human, in); err != nil {
			t.Fatal(grant, err)
		}
		human.ResourceGrants[0].ResourceID = "unrelated"
		if err := l.AuthorizeArtifactSignatureCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
			t.Fatal("wrong current local grant accepted", err)
		}
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "user", Scopes: []string{ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: release.ProductID, Scopes: []string{ScopeEvidenceWrite}}}}
	build, project, product := l.buildRuns["build"], l.projects["project"], l.products[release.ProductID]
	for _, mutate := range []func(){
		func() { v := product; v.TenantID = "other"; l.products[release.ProductID] = v },
		func() { v := project; v.TenantID = "other"; l.projects["project"] = v },
		func() { v := release; v.TenantID = "other"; l.releases[release.ID] = v },
		func() {
			v := build
			v.Outputs = []domain.BuildOutput{{ArtifactID: "artifact", Digest: "wrong-digest"}}
			l.buildRuns["build"] = v
		},
	} {
		mutate()
		if err := l.AuthorizeArtifactSignatureCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
			t.Fatal("stale/incoherent local artifact association authorized replay", err)
		}
		l.now = func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) }
		if _, err := l.CreateArtifactSignature(t.Context(), human, CreateArtifactSignatureInput{ArtifactID: in.ArtifactID, Algorithm: in.Algorithm, Signature: in.Signature}); !errors.Is(err, ErrForbidden) {
			t.Fatal("fresh local signature ignored current association", err)
		}
		l.now = func() time.Time { panic("local guard used clock") }
		l.buildRuns["build"], l.projects["project"], l.products[release.ProductID], l.releases[release.ID] = build, project, product, release
	}
	v := l.artifacts["artifact"]
	v.TenantID = "other"
	l.artifacts["artifact"] = v
	if err := l.AuthorizeArtifactSignatureCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign current artifact accepted", err)
	}
	if len(l.chain[a.TenantID]) != before || len(l.artifactSigs) != 0 {
		t.Fatal("local guard wrote effects")
	}
}
