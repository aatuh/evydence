package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type deploymentGuardFake struct {
	locks     []string
	artifacts []string
	denied    bool
	product   string
}

func (f *deploymentGuardFake) ExecuteEnvironment(ctx context.Context, fn func(context.Context, DeploymentEnvironmentTransaction) error) error {
	return fn(ctx, f)
}
func (f *deploymentGuardFake) ExecuteDeployment(ctx context.Context, fn func(context.Context, DeploymentTransaction) error) error {
	return fn(ctx, f)
}
func (f *deploymentGuardFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.denied && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *deploymentGuardFake) LockDeploymentTenant(context.Context, string) error {
	f.locks = append(f.locks, "tenant")
	return nil
}
func (f *deploymentGuardFake) LockEnvironmentProduct(context.Context, string, string) (EnvironmentProduct, error) {
	f.locks = append(f.locks, "product")
	return EnvironmentProduct{ID: f.product, TenantID: "tenant"}, nil
}
func (f *deploymentGuardFake) LockDeploymentEnvironment(context.Context, string, string) (DeploymentEnvironmentIdentity, error) {
	f.locks = append(f.locks, "environment")
	return DeploymentEnvironmentIdentity{ID: "env", TenantID: "tenant", ProductID: f.product}, nil
}
func (f *deploymentGuardFake) LockDeploymentRelease(context.Context, string, string) (DeploymentReleaseIdentity, error) {
	f.locks = append(f.locks, "release")
	return DeploymentReleaseIdentity{ID: "release", TenantID: "tenant", ProductID: "product"}, nil
}
func (f *deploymentGuardFake) CheckDeploymentArtifacts(_ context.Context, _ string, ids []string) error {
	f.locks = append(f.locks, "artifacts")
	f.artifacts = append([]string(nil), ids...)
	return nil
}
func (f *deploymentGuardFake) LockDeploymentRollback(context.Context, string, string) (DeploymentRollbackIdentity, error) {
	f.locks = append(f.locks, "rollback")
	return DeploymentRollbackIdentity{ID: "prior", TenantID: "tenant", EnvironmentID: "env"}, nil
}
func (*deploymentGuardFake) EnvironmentByName(context.Context, string, string, string) (operationsdomain.DeploymentEnvironment, bool, error) {
	panic("guard read environment metadata/natural-key reuse")
}
func (*deploymentGuardFake) InsertEnvironment(context.Context, operationsdomain.DeploymentEnvironment) error {
	panic("guard wrote environment")
}
func (*deploymentGuardFake) InsertDeployment(context.Context, operationsdomain.DeploymentEvent) error {
	panic("guard wrote deployment")
}
func (*deploymentGuardFake) WriteDeploymentEvidence(context.Context, identitydomain.Actor, DeploymentEvidenceInput) (string, error) {
	panic("guard generated evidence")
}
func (*deploymentGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard wrote audit")
}

func TestDeploymentCreationGuardsReadOnlyCurrentOwnershipAndPreserveDuplicates(t *testing.T) {
	f := &deploymentGuardFake{product: "product"}
	clock := application.ClockFunc(func() time.Time { panic("guard used clock") })
	ids := application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })
	e, err := NewDeploymentEnvironmentCommands(DeploymentEnvironmentConfig{Transactions: f, Authorizer: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDeploymentCommands(DeploymentConfig{Transactions: f, Authorizer: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"deployment:write"}}
	env := CreateEnvironmentInput{ProductID: "product", Name: "Production", Kind: "production"}
	in := RecordDeploymentInput{EnvironmentID: "env", ReleaseID: "release", Status: "succeeded", ArtifactIDs: []string{" b ", "a", "b"}, RollbackOf: "prior"}
	if err := e.AuthorizeEnvironmentCreation(t.Context(), a, env); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant", "product"}) {
		t.Fatal("environment guard used wrong reads", err, f)
	}
	f.locks = nil
	if err := d.AuthorizeDeploymentRecording(t.Context(), a, in); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant", "environment", "release", "artifacts", "rollback"}) || !reflect.DeepEqual(f.artifacts, []string{"a", "b", "b"}) {
		t.Fatal("deployment guard omitted coordinates or changed artifacts", err, f)
	}
	f.denied = true
	for _, check := range []func() error{func() error { return e.AuthorizeEnvironmentCreation(t.Context(), a, env) }, func() error { return d.AuthorizeDeploymentRecording(t.Context(), a, in) }} {
		if err := check(); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("removed grant retained replay", err)
		}
	}
	f.denied = false
	f.product = "other"
	if err := d.AuthorizeDeploymentRecording(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-product reference retained replay", err)
	}
}
