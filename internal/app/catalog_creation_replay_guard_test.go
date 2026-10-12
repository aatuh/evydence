package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestLocalCatalogCreationGuardsCheckCurrentAuthorityWithoutMetadataOrWrites(t *testing.T) {
	l := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Parent", "parent")
	if err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("catalog guard used clock") }
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeProductWrite, ScopeProjectWrite, ScopeReleaseWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: p.ID, Scopes: []string{ScopeProductWrite, ScopeProjectWrite, ScopeReleaseWrite}}}}
	product := releaseapp.CreateProductInput{Name: "New", Slug: "new"}
	project := releaseapp.CreateProjectInput{ProductID: p.ID, Name: "New"}
	release := releaseapp.CreateReleaseInput{ProductID: p.ID, Version: "2"}
	if err := l.AuthorizeProductCreation(t.Context(), human, product); !errors.Is(err, ErrForbidden) {
		t.Fatal("product-scoped grant created tenant root", err)
	}
	if err := l.AuthorizeProjectCreation(t.Context(), human, project); err != nil {
		t.Fatal(err)
	}
	if err := l.AuthorizeReleaseCreation(t.Context(), human, release); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = nil
	if err := l.AuthorizeProjectCreation(t.Context(), human, project); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained project replay", err)
	}
	if err := l.AuthorizeReleaseCreation(t.Context(), human, release); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained release replay", err)
	}
	foreign := p
	foreign.TenantID = "other"
	l.products[p.ID] = foreign
	if err := l.AuthorizeProjectCreation(t.Context(), a, project); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product retained project replay", err)
	}
	if err := l.AuthorizeReleaseCreation(t.Context(), a, release); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign product retained release replay", err)
	}
	delete(l.tenants, a.TenantID)
	if err := l.AuthorizeProductCreation(t.Context(), a, product); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant retained root creation", err)
	}
	if len(l.chain[a.TenantID]) != audits || len(l.projects) != 0 || len(l.releases) != 0 {
		t.Fatal("guard wrote catalog or audit")
	}
}
