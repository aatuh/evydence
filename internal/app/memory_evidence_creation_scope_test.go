package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func TestMemoryEvidenceCreationScopeSelectsOnlyCoherentOwnedCoordinates(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Evidence.(evidencequery.EvidenceCreationScopeReader)
	if !ok {
		t.Fatal("memory evidence lacks focused creation-scope reader")
	}
	// None of these descriptive/lifecycle fields belongs to an ownership
	// projection. Their corrupt values must not interfere with guard reads.
	p := tx.state.Products["tenant-product"]
	p.Name, p.Slug = strings.Repeat("private", 100000), "\x00"
	tx.state.Products[p.ID] = p
	j := tx.state.Projects["tenant-project"]
	j.Name = strings.Repeat("private", 100000)
	tx.state.Projects[j.ID] = j
	v := tx.state.Releases["tenant-release"]
	v.State, v.Version, v.Revision = "unknown", strings.Repeat("private", 100000), -1
	tx.state.Releases[v.ID] = v
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: j.ID, ReleaseID: v.ID}
	tx.state.DeploymentEnvironments["environment"] = domain.DeploymentEnvironment{ID: "environment", TenantID: "tenant", ProductID: p.ID}
	tx.state.DeploymentEvents["deployment"] = domain.DeploymentEvent{ID: "deployment", TenantID: "tenant", EnvironmentID: "environment", ReleaseID: v.ID}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input, want application.ResourceReferences
	}{
		{},
		{application.ResourceReferences{ProductID: p.ID}, application.ResourceReferences{ProductID: p.ID}},
		{application.ResourceReferences{ProjectID: j.ID}, application.ResourceReferences{ProductID: p.ID, ProjectID: j.ID}},
		{application.ResourceReferences{ReleaseID: v.ID}, application.ResourceReferences{ProductID: p.ID, ReleaseID: v.ID}},
		{application.ResourceReferences{ProjectID: j.ID, ReleaseID: v.ID}, application.ResourceReferences{ProductID: p.ID, ProjectID: j.ID, ReleaseID: v.ID}},
		{application.ResourceReferences{BuildID: "build"}, application.ResourceReferences{ProductID: p.ID, ProjectID: j.ID, ReleaseID: v.ID, BuildID: "build"}},
		{application.ResourceReferences{DeploymentID: "deployment"}, application.ResourceReferences{ProductID: p.ID, ReleaseID: v.ID, DeploymentID: "deployment"}},
	} {
		got, err := r.ResolveEvidenceCreationScope(t.Context(), "tenant", tc.input)
		if err != nil || got != tc.want {
			t.Fatal("ownership-only scope lost complete coherent coordinates", got, tc.want, err)
		}
	}
	for _, input := range []application.ResourceReferences{
		{ProductID: "foreign-product"}, {ProjectID: "foreign-project"}, {ReleaseID: "foreign-release"},
		{ProductID: "foreign-product", ReleaseID: v.ID}, {ProjectID: "foreign-project", ReleaseID: v.ID},
		{ReleaseID: "missing"}, {BuildID: "missing"}, {DeploymentID: "missing"},
	} {
		got, err := r.ResolveEvidenceCreationScope(t.Context(), "tenant", input)
		if !errors.Is(err, ErrNotFound) || got != (application.ResourceReferences{}) {
			t.Fatal("foreign/incoherent/missing scope returned coordinates", got, err)
		}
	}
	for _, input := range []application.ResourceReferences{{ProductID: " padded "}, {ReleaseID: strings.Repeat("x", 1025)}, {ArtifactID: "unexpected"}} {
		if got, err := r.ResolveEvidenceCreationScope(t.Context(), "tenant", input); !errors.Is(err, ErrValidation) || got != (application.ResourceReferences{}) {
			t.Fatal("malformed scope returned partial coordinates", got, err)
		}
	}
	if _, err := r.ResolveEvidenceCreationScope(t.Context(), "unknown", application.ResourceReferences{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("empty scope did not check current tenant", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := r.ResolveEvidenceCreationScope(ctx, "tenant", application.ResourceReferences{ReleaseID: v.ID}); !errors.Is(err, context.Canceled) || got != (application.ResourceReferences{}) {
		t.Fatal("cancelled scope returned data", got, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("scope read changed any repository state")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveEvidenceCreationScope(t.Context(), "tenant", application.ResourceReferences{}); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned scope", err)
	}
}
