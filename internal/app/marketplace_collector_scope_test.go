package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func marketplaceLocalFixture(t *testing.T) (*Ledger, domain.Actor, CreateMarketplaceCollectorInput) {
	t.Helper()
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	return l, a, CreateMarketplaceCollectorInput{Name: "Scanner", Provider: "scanner", Version: "1.0", Publisher: "publisher", ManifestHash: "sha256:" + strings.Repeat("A", 64)}
}
func TestMarketplaceCreationLocalRequiresTenantWideHumanAdministration(t *testing.T) {
	l, a, in := marketplaceLocalFixture(t)
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopeCollectorAdmin}}}
	if v, err := l.CreateMarketplaceCollector(t.Context(), a, in); !errors.Is(err, ErrForbidden) || v.ID != "" || len(l.marketplaceCollectors) != 0 {
		t.Fatal("product grant created tenant-wide collector", v, err)
	}
}
func TestMarketplaceCreationLocalRawBoundsAndNULBeforeTrim(t *testing.T) {
	for _, mode := range []string{"name", "provider", "version", "publisher", "nul", "utf8"} {
		t.Run(mode, func(t *testing.T) {
			l, a, in := marketplaceLocalFixture(t)
			switch mode {
			case "name":
				in.Name = strings.Repeat(" ", 257) + in.Name
			case "provider":
				in.Provider = strings.Repeat(" ", 257) + in.Provider
			case "version":
				in.Version = strings.Repeat(" ", 129) + in.Version
			case "publisher":
				in.Publisher = strings.Repeat(" ", 257) + in.Publisher
			case "nul":
				in.Name = "label\x00"
			case "utf8":
				in.Name = string([]byte{255})
			}
			if v, err := l.CreateMarketplaceCollector(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(l.marketplaceCollectors) != 0 {
				t.Fatal("unsafe collector metadata published", v, err)
			}
		})
	}
}
func TestMarketplaceCreationLocalReturnsImmutableLimitations(t *testing.T) {
	for _, surface := range []string{"create", "list", "health"} {
		t.Run(surface, func(t *testing.T) {
			l, a, in := marketplaceLocalFixture(t)
			v, err := l.CreateMarketplaceCollector(t.Context(), a, in)
			if err != nil {
				t.Fatal(err)
			}
			switch surface {
			case "list":
				items, err := l.ListMarketplaceCollectors(t.Context(), a)
				if err != nil {
					t.Fatal(err)
				}
				v = items[0]
			case "health":
				report, err := l.MarketplaceCollectorHealth(t.Context(), a, v.ID)
				if err != nil {
					t.Fatal(err)
				}
				v = report.Collector
			}
			v.Limitations[0] = "changed"
			if l.marketplaceCollectors[v.ID].Limitations[0] == "changed" {
				t.Fatal("returned collector aliases stored limitations")
			}
		})
	}
}
