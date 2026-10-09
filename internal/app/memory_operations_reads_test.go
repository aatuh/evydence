package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func memoryOperationsReadFixture(t *testing.T) (*MemoryUnitOfWorkFactory, *memoryUnitOfWork) {
	t.Helper()
	factory, tx := memoryGovernanceReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.Projects[tenant+"-project"] = domain.Project{ID: tenant + "-project", TenantID: tenant, ProductID: tenant + "-product"}
		tx.state.Incidents[tenant+"-incident"] = domain.Incident{ID: tenant + "-incident", TenantID: tenant, ProductID: tenant + "-product", ReleaseID: tenant + "-release", Title: strings.Repeat("private", 10000)}
		tx.state.BuildRuns[tenant+"-build"] = domain.BuildRun{ID: tenant + "-build", TenantID: tenant, ProjectID: tenant + "-project", ReleaseID: tenant + "-release"}
		tx.state.DeploymentEnvironments[tenant+"-environment"] = domain.DeploymentEnvironment{ID: tenant + "-environment", TenantID: tenant, ProductID: tenant + "-product"}
		tx.state.DeploymentEvents[tenant+"-deployment"] = domain.DeploymentEvent{ID: tenant + "-deployment", TenantID: tenant, EnvironmentID: tenant + "-environment", ReleaseID: tenant + "-release"}
		tx.state.Evidence[tenant+"-build-evidence"] = domain.EvidenceItem{ID: tenant + "-build-evidence", TenantID: tenant, BuildID: tenant + "-build", DeploymentID: tenant + "-deployment", Metadata: map[string]any{"private": strings.Repeat("secret", 10000)}}
	}
	return factory, tx
}

func TestMemoryOperationsReadersExposeOnlyCoherentCurrentCoordinates(t *testing.T) {
	factory, tx := memoryOperationsReadFixture(t)
	reader, ok := tx.Repositories().Risk.(operationsapp.IncidentReader)
	if !ok {
		t.Fatal("memory adapter lacks focused incident ownership reader")
	}
	locker, ok := tx.Repositories().Governance.(operationsapp.RetentionMarkerScopeLocker)
	if !ok {
		t.Fatal("memory adapter lacks focused retention scope locker")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, id string
		refs     application.ResourceReferences
	}{
		{"product", "tenant-product", application.ResourceReferences{ProductID: "tenant-product"}},
		{"release", "tenant-release", application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}},
		{"incident", "tenant-incident", application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}},
		{"evidence", "tenant-evidence", application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}},
		{"evidence", "tenant-build-evidence", application.ResourceReferences{ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", BuildID: "tenant-build", DeploymentID: "tenant-deployment"}},
	} {
		v, err := reader.ReadIncidentSubject(t.Context(), "tenant", tc.kind, tc.id)
		want := operationsapp.IncidentSubject{ID: tc.id, TenantID: "tenant", Type: tc.kind, Resources: tc.refs}
		if err != nil || v != want {
			t.Fatal("incident reader lost coherent coordinates", tc.kind, v, err)
		}
	}
	for _, tc := range []struct{ kind, id string }{{"tenant", "tenant"}, {"product", "tenant-product"}, {"project", "tenant-project"}, {"release", "tenant-release"}, {"evidence", "tenant-build-evidence"}} {
		if err := locker.LockRetentionMarkerScope(t.Context(), "tenant", tc.kind, tc.id); err != nil {
			t.Fatal("owned retention root rejected", tc, err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("ownership readers changed pending state")
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(committed, after) {
		t.Fatal("ownership readers changed committed state", err)
	}
}

func TestMemoryOperationsReadersRejectForeignMalformedAndBrokenParents(t *testing.T) {
	_, tx := memoryOperationsReadFixture(t)
	reader, ok := tx.Repositories().Risk.(operationsapp.IncidentReader)
	if !ok {
		t.Fatal("memory incident reader missing")
	}
	locker, ok := tx.Repositories().Governance.(operationsapp.RetentionMarkerScopeLocker)
	if !ok {
		t.Fatal("memory retention locker missing")
	}
	for _, tc := range []struct{ kind, id string }{{"product", "foreign-product"}, {"release", "foreign-release"}, {"incident", "foreign-incident"}, {"evidence", "foreign-evidence"}, {"incident", "missing"}} {
		if _, err := reader.ReadIncidentSubject(t.Context(), "tenant", tc.kind, tc.id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/missing incident subject accepted", tc, err)
		}
	}
	for _, tc := range []struct{ kind, id string }{{"tenant", "foreign"}, {"product", "foreign-product"}, {"project", "foreign-project"}, {"release", "foreign-release"}, {"evidence", "foreign-evidence"}} {
		if err := locker.LockRetentionMarkerScope(t.Context(), "tenant", tc.kind, tc.id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign retention root accepted", tc, err)
		}
	}
	for _, id := range []string{"", " tenant-product", "bad\x00", strings.Repeat("x", 1025)} {
		if _, err := reader.ReadIncidentSubject(t.Context(), "tenant", "product", id); !errors.Is(err, ErrValidation) {
			t.Fatal("malformed ownership id accepted", err)
		}
	}
	if _, err := reader.ReadIncidentSubject(t.Context(), "tenant", "unknown", "tenant-product"); !errors.Is(err, ErrValidation) {
		t.Fatal("unknown incident kind accepted", err)
	}
	if err := locker.LockRetentionMarkerScope(t.Context(), "tenant", "unknown", "tenant-product"); !errors.Is(err, ErrValidation) {
		t.Fatal("unknown retention kind accepted", err)
	}
	for _, mutate := range []func(*MemoryUnitOfWorkSnapshot){
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["tenant-build"]
			v.ProjectID = "foreign-project"
			s.BuildRuns[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ProductID = "foreign-product"
			s.Releases[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.DeploymentEnvironments["tenant-environment"]
			v.ProductID = "foreign-product"
			s.DeploymentEnvironments[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-build-evidence"]
			v.ReleaseID = "foreign-release"
			s.Evidence[v.ID] = v
		},
	} {
		before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&tx.state)
		if _, err := reader.ReadIncidentSubject(t.Context(), "tenant", "evidence", "tenant-build-evidence"); !errors.Is(err, ErrNotFound) {
			t.Fatal("broken evidence parents authorized", err)
		}
		tx.state = before
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadIncidentSubject(cancelled, "tenant", "incident", "tenant-incident"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled ownership read accepted", err)
	}
	if err := locker.LockRetentionMarkerScope(cancelled, "tenant", "product", "tenant-product"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled retention root accepted", err)
	}
}
