package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestSourceRepositoryCreationAuthorizesExistingOwnerAndDetachedScope(t *testing.T) {
	ledger := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
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

func TestLocalSourceRepositoryCreationGuardUsesCurrentCoordinatesAndRawBounds(t *testing.T) {
	l := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Source", "source")
	if err != nil {
		t.Fatal(err)
	}
	project, err := l.CreateProject(t.Context(), a, p.ID, "Source")
	if err != nil {
		t.Fatal(err)
	}
	in := CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "org/api"}
	repo, err := l.CreateSourceRepository(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := any(l).(interface {
		AuthorizeSourceRepositoryCreation(context.Context, domain.Actor, CreateRepositoryInput) error
	})
	if !ok {
		t.Fatal("local source creation has no replay guard")
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeSourceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{ScopeSourceWrite}}}}
	if err := guard.AuthorizeSourceRepositoryCreation(t.Context(), human, in); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = nil
	if err := guard.AuthorizeSourceRepositoryCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained replay", err)
	}
	stored := l.repositories[repo.ID]
	stored.CloneURL = strings.Repeat("x", 9000000)
	l.repositories[repo.ID] = stored
	if err := guard.AuthorizeSourceRepositoryCreation(t.Context(), a, in); err != nil {
		t.Fatal("guard read private metadata", err)
	}
	product := l.products[p.ID]
	product.TenantID = "other"
	l.products[p.ID] = product
	if err := guard.AuthorizeSourceRepositoryCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product accepted", err)
	}
	if _, err := l.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("fresh creation ignored foreign product", err)
	}
	product.TenantID = a.TenantID
	l.products[p.ID] = product
	delete(l.tenants, a.TenantID)
	if err := guard.AuthorizeSourceRepositoryCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant accepted", err)
	}
	in.ProjectID = strings.Repeat(" ", 1025) + project.ID
	if _, err := l.CreateSourceRepository(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("raw padding bypassed local bound", err)
	}
}
