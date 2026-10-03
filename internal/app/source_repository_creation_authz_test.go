package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestSourceRepositoryCreationAuthorizesExistingOwnerAndDetachedScope(t *testing.T) {
	ledger := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, admin := bootstrapEnterpriseTestTenant(t, ledger)
	product, err := ledger.CreateProduct(t.Context(), admin, "Source", "source")
	if err != nil {
		t.Fatal(err)
	}
	one, err := ledger.CreateProject(t.Context(), admin, product.ID, "One")
	if err != nil {
		t.Fatal(err)
	}
	two, err := ledger.CreateProject(t.Context(), admin, product.ID, "Two")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := ledger.CreateSourceRepository(t.Context(), admin, CreateRepositoryInput{ProjectID: two.ID, Provider: "github", FullName: "org/private", CloneURL: "https://example.test/private"})
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: admin.TenantID, UserID: "human", Scopes: []string{ScopeSourceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: one.ID, Scopes: []string{ScopeSourceWrite}}}}
	for _, input := range []CreateRepositoryInput{{ProjectID: one.ID, Provider: "github", FullName: repository.FullName}, {Provider: "github", FullName: "org/detached"}} {
		if v, err := ledger.CreateSourceRepository(t.Context(), human, input); !errors.Is(err, ErrForbidden) || v.ID != "" {
			t.Fatal("unauthorized repository returned or created", v, err)
		}
	}
}
