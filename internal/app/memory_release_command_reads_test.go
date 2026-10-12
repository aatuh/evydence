package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type memoryReleaseCommandTestReader interface {
	releaseapp.BuildIdentityReader
	releaseapp.BuildCreationGuardReader
	releaseapp.ReleaseTransitionGuardReader
	releaseapp.CandidateReleaseReader
	releaseapp.ReleaseCandidateReferenceValidator
	releaseapp.CandidateStateReader
	releaseapp.CandidateTransitionGuardReader
}

func TestMemoryReleaseCommandReadersSelectCurrentOwnedIdentitiesWithoutDescriptions(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(memoryReleaseCommandTestReader)
	if !ok {
		t.Fatal("memory release repository lacks focused command readers")
	}
	p := tx.state.Projects["tenant-project"]
	p.Name = strings.Repeat("private", 10000)
	tx.state.Projects[p.ID] = p
	release := tx.state.Releases["tenant-release"]
	release.Version = "recorded-version"
	release.State = "invalid-state"
	tx.state.Releases[release.ID] = release
	project, err := r.ReadBuildProject(t.Context(), "tenant", p.ID)
	if err != nil || project != (releasedomain.Project{ID: p.ID, TenantID: p.TenantID, ProductID: p.ProductID}) {
		t.Fatal("build identity read descriptive project fields", err)
	}
	parent, err := r.ReadBuildRelease(t.Context(), "tenant", release.ID)
	if err != nil || parent.ID != release.ID || parent.ProductID != release.ProductID || parent.Version != release.Version || !parent.CreatedAt.IsZero() {
		t.Fatal("build release identity omitted version or selected lifecycle data", err)
	}
	transition, err := r.ReadReleaseTransitionScope(t.Context(), "tenant", release.ID)
	if err != nil || transition != (releaseapp.ReleaseTransitionScope{ID: release.ID, TenantID: "tenant", ProductID: release.ProductID}) {
		t.Fatal("transition preflight inspected invalid lifecycle metadata", err)
	}
	if v, err := r.ReadBuildProject(t.Context(), "foreign", p.ID); !errors.Is(err, ErrNotFound) || v != (releasedomain.Project{}) {
		t.Fatal("build parent crossed tenant boundary", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ReadBuildRelease(ctx, "tenant", release.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, releasedomain.Release{}) {
		t.Fatal("cancelled identity read returned data", err)
	}
}

func TestMemoryCandidateReferenceReaderRequiresOwnedSourceReleaseBindingsAndBounds(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(memoryReleaseCommandTestReader)
	if !ok {
		t.Fatal("focused candidate reference reader missing")
	}
	e := domain.EvidenceItem{ID: "e", TenantID: "tenant", ReleaseID: "tenant-release", Type: "sbom", Metadata: map[string]any{"invalid": make(chan int)}}
	tx.state.Evidence[e.ID] = e
	tx.state.SBOMs["sbom"] = domain.SBOM{ID: "sbom", TenantID: "tenant", ReleaseID: "tenant-release", EvidenceID: e.ID}
	refs := releaseapp.ReleaseCandidateReferences{SBOMIDs: []string{"sbom"}}
	if err := r.ValidateReleaseCandidateReferences(t.Context(), "tenant", "tenant-release", refs); err != nil {
		t.Fatal("identity-only candidate lookup read private document metadata", err)
	}
	e.ReleaseID = "foreign-release"
	tx.state.Evidence[e.ID] = e
	if err := r.ValidateReleaseCandidateReferences(t.Context(), "tenant", "tenant-release", refs); !errors.Is(err, ErrNotFound) {
		t.Fatal("candidate accepted misbound source evidence", err)
	}
	if err := r.ValidateReleaseCandidateReferences(t.Context(), "foreign", "foreign-release", refs); !errors.Is(err, ErrNotFound) {
		t.Fatal("candidate accepted foreign reference", err)
	}
	refs.SBOMIDs = make([]string, 4097)
	if err := r.ValidateReleaseCandidateReferences(t.Context(), "tenant", "tenant-release", refs); !errors.Is(err, ErrValidation) {
		t.Fatal("candidate reference row budget ignored", err)
	}
}
