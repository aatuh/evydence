package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func memoryDeploymentPointFixture(t *testing.T) (*memoryUnitOfWork, operationsquery.DeploymentPointReader, domain.DeploymentEvent) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Deployments.(operationsquery.DeploymentPointReader)
	if !ok {
		t.Fatal("memory deployment repository lacks focused point reader")
	}
	finished := fixedNow().Add(time.Hour)
	v := domain.DeploymentEvent{ID: "deployment", TenantID: "tenant", EnvironmentID: "environment", ReleaseID: "tenant-release", ArtifactIDs: []string{"artifact-1", "artifact-2"}, Status: "succeeded", StartedAt: fixedNow(), FinishedAt: &finished, RollbackOf: "previous", EvidenceID: "recorded-evidence", SchemaVersion: "1", CreatedAt: fixedNow()}
	tx.state.DeploymentEnvironments[v.EnvironmentID] = domain.DeploymentEnvironment{ID: v.EnvironmentID, TenantID: v.TenantID, ProductID: "tenant-product"}
	tx.state.DeploymentEvents[v.ID] = v
	return tx, reader, v
}

func TestMemoryDeploymentPointKeepsPublicFieldsAndDetachesMutableData(t *testing.T) {
	tx, reader, want := memoryDeploymentPointFixture(t)
	p := tx.state.Products["tenant-product"]
	p.Name = strings.Repeat("unselected-product", 10000)
	tx.state.Products[p.ID] = p
	e := tx.state.DeploymentEnvironments[want.EnvironmentID]
	e.Name, e.Kind = strings.Repeat("unselected-environment", 10000), "unselected"
	tx.state.DeploymentEnvironments[e.ID] = e
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	point, err := reader.GetDeploymentPoint(t.Context(), "tenant", want.ID)
	if err != nil || point.ProductID != p.ID || !reflect.DeepEqual(point.Deployment, operationsdomain.DeploymentEvent(want)) {
		t.Fatal("point lost public fields or consulted unselected metadata", err)
	}
	point.Deployment.ArtifactIDs[0] = "changed"
	*point.Deployment.FinishedAt = point.Deployment.FinishedAt.Add(time.Hour)
	again, err := reader.GetDeploymentPoint(t.Context(), "tenant", want.ID)
	if err != nil || !reflect.DeepEqual(again.Deployment, operationsdomain.DeploymentEvent(want)) || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("point exposed stored aliases or changed repository state", err)
	}
}

func TestMemoryDeploymentPointRejectsIncoherentCurrentParents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*MemoryUnitOfWorkSnapshot)
	}{
		{"foreign deployment", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.DeploymentEvents["deployment"]
			v.TenantID = "foreign"
			s.DeploymentEvents[v.ID] = v
		}},
		{"mismatched deployment identity", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.DeploymentEvents["deployment"]
			v.ID = "other"
			s.DeploymentEvents["deployment"] = v
		}},
		{"missing environment", func(s *MemoryUnitOfWorkSnapshot) { delete(s.DeploymentEnvironments, "environment") }},
		{"foreign environment", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.DeploymentEnvironments["environment"]
			v.TenantID = "foreign"
			s.DeploymentEnvironments[v.ID] = v
		}},
		{"mismatched environment identity", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.DeploymentEnvironments["environment"]
			v.ID = "other"
			s.DeploymentEnvironments["environment"] = v
		}},
		{"missing release", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Releases, "tenant-release") }},
		{"foreign release", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.TenantID = "foreign"
			s.Releases[v.ID] = v
		}},
		{"mismatched release identity", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ID = "other"
			s.Releases["tenant-release"] = v
		}},
		{"different products", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ProductID = "foreign-product"
			s.Releases[v.ID] = v
		}},
		{"missing product", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Products, "tenant-product") }},
		{"foreign product", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Products["tenant-product"]
			v.TenantID = "foreign"
			s.Products[v.ID] = v
		}},
		{"mismatched product identity", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Products["tenant-product"]
			v.ID = "other"
			s.Products["tenant-product"] = v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, reader, v := memoryDeploymentPointFixture(t)
			tc.change(&tx.state)
			out, err := reader.GetDeploymentPoint(t.Context(), "tenant", v.ID)
			if !errors.Is(err, operationsquery.ErrNotFound) || !reflect.DeepEqual(out, operationsquery.DeploymentPoint{}) {
				t.Fatal("incoherent point exposed data", err)
			}
		})
	}
}

func TestMemoryDeploymentQueryRequiresCurrentProductOrReleaseGrant(t *testing.T) {
	_, reader, want := memoryDeploymentPointFixture(t)
	query, err := operationsquery.NewDeploymentPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"tenant", "product", "release", "project", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			id := map[string]string{"tenant": "tenant", "product": "tenant-product", "release": "tenant-release", "project": "tenant-project"}[kind]
			a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"deployment:read"}}
			if kind != "revoked" {
				a.ResourceGrants = []domain.ResourceGrant{{ResourceType: kind, ResourceID: id, Scopes: []string{"deployment:read"}}}
			}
			v, err := query.GetDeployment(t.Context(), a, want.ID)
			if kind == "project" || kind == "revoked" {
				if !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) {
					t.Fatal("unrelated/revoked grant disclosed deployment", err)
				}
			} else if err != nil || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent(want)) {
				t.Fatal("owned deployment grant denied or changed fields", err)
			}
		})
	}
}

func TestMemoryDeploymentPointRejectsInvalidAndClosedReads(t *testing.T) {
	tx, reader, v := memoryDeploymentPointFixture(t)
	for _, tc := range []struct{ tenant, id string }{{"", v.ID}, {" tenant", v.ID}, {"tenant", ""}, {"tenant", strings.Repeat("x", 1025)}} {
		if out, err := reader.GetDeploymentPoint(t.Context(), tc.tenant, tc.id); err == nil || !reflect.DeepEqual(out, operationsquery.DeploymentPoint{}) {
			t.Fatal("invalid coordinates disclosed point", err)
		}
	}
	var missingContext context.Context
	if _, err := reader.GetDeploymentPoint(missingContext, "tenant", v.ID); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.GetDeploymentPoint(ctx, "tenant", v.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated", err)
	}
	if _, err := reader.GetDeploymentPoint(t.Context(), "foreign", v.ID); !errors.Is(err, operationsquery.ErrNotFound) {
		t.Fatal("foreign tenant disclosed point", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if out, err := reader.GetDeploymentPoint(t.Context(), "tenant", v.ID); err == nil || !reflect.DeepEqual(out, operationsquery.DeploymentPoint{}) {
		t.Fatal("closed transaction disclosed point", err)
	}
}
