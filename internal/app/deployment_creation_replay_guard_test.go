package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestLocalDeploymentCreationGuardsCheckCurrentOwnershipWithoutEffects(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Parent", "parent")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	e, err := l.CreateDeploymentEnvironment(t.Context(), a, CreateEnvironmentInput{ProductID: p.ID, Name: "Production", Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := l.RecordDeployment(t.Context(), a, RecordDeploymentInput{EnvironmentID: e.ID, ReleaseID: r.ID, Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID}
	counts := func() [4]int {
		return [4]int{len(l.environments), len(l.deployments), len(l.evidence), len(l.chain[a.TenantID])}
	}
	baseline := counts()
	l.now = func() time.Time { panic("deployment replay guard used clock") }
	env := operationsapp.CreateEnvironmentInput{ProductID: p.ID, Name: "Production", Kind: "production"}
	in := operationsapp.RecordDeploymentInput{EnvironmentID: e.ID, ReleaseID: r.ID, Status: "rolled_back", ArtifactIDs: []string{"artifact", "artifact"}, RollbackOf: rollback.ID}
	checks := []func(domain.Actor) error{func(a domain.Actor) error { return l.AuthorizeEnvironmentCreation(t.Context(), a, env) }, func(a domain.Actor) error { return l.AuthorizeDeploymentRecording(t.Context(), a, in) }}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeDeploymentWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: p.ID, Scopes: []string{ScopeDeploymentWrite}}}}
	for _, check := range checks {
		if err := check(human); err != nil {
			t.Fatal(err)
		}
	}
	human.ResourceGrants = nil
	for _, check := range checks {
		if err := check(human); !errors.Is(err, ErrForbidden) {
			t.Fatal("removed grant retained deployment replay", err)
		}
	}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: r.ID, Scopes: []string{ScopeDeploymentWrite}}}
	if err := checks[0](human); !errors.Is(err, ErrForbidden) {
		t.Fatal("release grant authorized product-wide environment", err)
	}
	if err := checks[1](human); err != nil {
		t.Fatal("release grant rejected deployment", err)
	}
	// Existing private metadata and lifecycle do not decide replay authority.
	changedEnv := e
	changedEnv.Kind = "private-invalid-metadata"
	l.environments[e.ID] = changedEnv
	changedRelease := r
	changedRelease.State = "private-invalid-state"
	l.releases[r.ID] = changedRelease
	for _, check := range checks {
		if err := check(a); err != nil {
			t.Fatal("deployment guard reread private metadata", err)
		}
	}
	changedProduct := p
	changedProduct.TenantID = "other"
	l.products[p.ID] = changedProduct
	for _, check := range checks {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign product retained replay", err)
		}
	}
	l.products[p.ID] = p
	changedRelease.ProductID = "other-product"
	l.releases[r.ID] = changedRelease
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("incoherent product retained deployment replay", err)
	}
	l.releases[r.ID] = r
	changedEnv.TenantID = "other"
	l.environments[e.ID] = changedEnv
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign environment retained deployment replay", err)
	}
	l.environments[e.ID] = e
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "other"}
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign artifact retained deployment replay", err)
	}
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID}
	changedRollback := rollback
	changedRollback.EnvironmentID = "other-environment"
	l.deployments[rollback.ID] = changedRollback
	if err := checks[1](a); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign environment rollback retained replay", err)
	}
	if counts() != baseline {
		t.Fatal("deployment guard wrote effects", counts(), baseline)
	}
}
