package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func memoryDeploymentWriteFixture(t *testing.T) (*memoryUnitOfWork, operationsapp.DeploymentEnvironmentReader, operationsapp.DeploymentReader, operationsapp.DeploymentTenantLocker) {
	t.Helper()
	tx, _, _ := memoryDeploymentPointFixture(t)
	environments, ok := tx.Repositories().Deployments.(operationsapp.DeploymentEnvironmentReader)
	if !ok {
		t.Fatal("deployment repository lacks focused environment write reader")
	}
	deployments, ok := tx.Repositories().Deployments.(operationsapp.DeploymentReader)
	if !ok {
		t.Fatal("deployment repository lacks focused deployment write reader")
	}
	tenant, ok := tx.Repositories().Deployments.(operationsapp.DeploymentTenantLocker)
	if !ok {
		t.Fatal("deployment repository lacks focused tenant guard")
	}
	e := tx.state.DeploymentEnvironments["environment"]
	e.Name, e.Kind, e.SchemaVersion, e.CreatedAt = "Production", "production", operationsdomain.DeploymentEnvironmentVersion, fixedNow()
	tx.state.DeploymentEnvironments[e.ID] = e
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant"}
	return tx, environments, deployments, tenant
}

func TestMemoryDeploymentWriteReadersKeepCurrentCoordinatesAndBoundNamedMetadata(t *testing.T) {
	tx, envs, deps, tenant := memoryDeploymentWriteFixture(t)
	p := tx.state.Products["tenant-product"]
	p.Name = strings.Repeat("unselected-product", 10000)
	tx.state.Products[p.ID] = p
	a := tx.state.Artifacts["artifact"]
	a.Name = strings.Repeat("unselected-artifact", 10000)
	tx.state.Artifacts[a.ID] = a
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenant.LockDeploymentTenant(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if v, err := envs.LockEnvironmentProduct(t.Context(), "tenant", p.ID); err != nil || v != (operationsapp.EnvironmentProduct{ID: p.ID, TenantID: "tenant"}) {
		t.Fatal("product identity consulted unrelated metadata", err)
	}
	if v, err := deps.LockDeploymentEnvironment(t.Context(), "tenant", "environment"); err != nil || v != (operationsapp.DeploymentEnvironmentIdentity{ID: "environment", TenantID: "tenant", ProductID: p.ID}) {
		t.Fatal("environment identity changed", err)
	}
	if v, err := deps.LockDeploymentRelease(t.Context(), "tenant", "tenant-release"); err != nil || v != (operationsapp.DeploymentReleaseIdentity{ID: "tenant-release", TenantID: "tenant", ProductID: p.ID}) {
		t.Fatal("release identity changed", err)
	}
	if v, err := deps.LockDeploymentRollback(t.Context(), "tenant", "deployment"); err != nil || v != (operationsapp.DeploymentRollbackIdentity{ID: "deployment", TenantID: "tenant", EnvironmentID: "environment"}) {
		t.Fatal("rollback identity changed", err)
	}
	if err := deps.CheckDeploymentArtifacts(t.Context(), "tenant", []string{"artifact", "artifact"}); err != nil {
		t.Fatal("owned artifact identities or duplicate semantics changed", err)
	}
	if v, found, err := envs.EnvironmentByName(t.Context(), "tenant", p.ID, "Production"); err != nil || !found || v != operationsdomain.DeploymentEnvironment(tx.state.DeploymentEnvironments["environment"]) {
		t.Fatal("named environment lost full metadata", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("write preflight readers mutated state")
	}
	e := tx.state.DeploymentEnvironments["environment"]
	e.Kind = strings.Repeat("k", operationsapp.MaxEnvironmentTextBytes)
	tx.state.DeploymentEnvironments[e.ID] = e
	if _, found, err := envs.EnvironmentByName(t.Context(), "tenant", p.ID, e.Name); err != nil || !found {
		t.Fatal("exact named metadata bound rejected", err)
	}
	e.Kind += "k"
	tx.state.DeploymentEnvironments[e.ID] = e
	if v, found, err := envs.EnvironmentByName(t.Context(), "tenant", p.ID, e.Name); !errors.Is(err, ErrConflict) || found || v != (operationsdomain.DeploymentEnvironment{}) {
		t.Fatal("oversized selected metadata exposed record", err)
	}
	e.Kind = "production"
	e.ID = "duplicate"
	tx.state.DeploymentEnvironments[e.ID] = e
	if v, found, err := envs.EnvironmentByName(t.Context(), "tenant", p.ID, e.Name); !errors.Is(err, ErrConflict) || found || v != (operationsdomain.DeploymentEnvironment{}) {
		t.Fatal("ambiguous natural key exposed record", err)
	}
}

func TestMemoryDeploymentWriteReadersRejectForeignMissingAndClosedState(t *testing.T) {
	tx, envs, deps, tenant := memoryDeploymentWriteFixture(t)
	if _, err := envs.LockEnvironmentProduct(t.Context(), "tenant", "foreign-product"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product accepted", err)
	}
	if _, err := deps.LockDeploymentEnvironment(t.Context(), "foreign", "environment"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign environment accepted", err)
	}
	if _, err := deps.LockDeploymentRelease(t.Context(), "tenant", "foreign-release"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign release accepted", err)
	}
	if _, err := deps.LockDeploymentRollback(t.Context(), "foreign", "deployment"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign rollback accepted", err)
	}
	if err := deps.CheckDeploymentArtifacts(t.Context(), "foreign", []string{"artifact"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign artifact accepted", err)
	}
	if err := deps.CheckDeploymentArtifacts(t.Context(), "tenant", make([]string, operationsapp.MaxDeploymentArtifacts+1)); !errors.Is(err, ErrValidation) {
		t.Fatal("unbounded artifacts accepted", err)
	}
	delete(tx.state.Products, "tenant-product")
	if _, err := deps.LockDeploymentEnvironment(t.Context(), "tenant", "environment"); !errors.Is(err, ErrNotFound) {
		t.Fatal("dangling environment accepted", err)
	}
	if _, err := deps.LockDeploymentRelease(t.Context(), "tenant", "tenant-release"); !errors.Is(err, ErrNotFound) {
		t.Fatal("dangling release accepted", err)
	}
	var missingContext context.Context
	if err := tenant.LockDeploymentTenant(missingContext, "tenant"); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := deps.CheckDeploymentArtifacts(ctx, "tenant", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("empty artifact check ignored cancellation", err)
	}
	if err := tenant.LockDeploymentTenant(t.Context(), "missing"); err == nil {
		t.Fatal("missing tenant accepted")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := envs.LockEnvironmentProduct(t.Context(), "tenant", "tenant-product"); err == nil {
		t.Fatal("closed transaction read product")
	}
}
