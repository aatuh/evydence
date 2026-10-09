package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func saasLocalFixture(t *testing.T) (*Ledger, domain.Actor, CreateSaaSEditionProfileInput) {
	t.Helper()
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow})
	tenant, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	return l, a, CreateSaaSEditionProfileInput{Name: "hosted", Region: "eu", AdminTenantID: tenant.ID, IsolationModel: "shared-control-plane"}
}

func TestSaaSProfileLocalRawBoundsAndAuthenticatedActor(t *testing.T) {
	for _, field := range []string{"name", "region", "admin", "isolation", "anonymous"} {
		t.Run(field, func(t *testing.T) {
			l, a, in := saasLocalFixture(t)
			want := ErrValidation
			switch field {
			case "name":
				in.Name = strings.Repeat(" ", 257) + in.Name
			case "region":
				in.Region = strings.Repeat(" ", 129) + in.Region
			case "admin":
				in.AdminTenantID = strings.Repeat(" ", 1025) + in.AdminTenantID
			case "isolation":
				in.IsolationModel = "model\x00"
			case "anonymous":
				a.KeyID = ""
				want = ErrUnauthorized
			}
			v, err := l.CreateSaaSEditionProfile(t.Context(), a, in)
			if !errors.Is(err, want) || v.ID != "" || len(l.saasProfiles) != 0 {
				t.Fatal("unsafe profile was published", v, err)
			}
		})
	}
}

func TestSaaSProfileLocalReturnedLimitationsAreImmutable(t *testing.T) {
	l, a, in := saasLocalFixture(t)
	v, err := l.CreateSaaSEditionProfile(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	v.Limitations[0] = "changed"
	if l.saasProfiles[v.ID].Limitations[0] == "changed" {
		t.Fatal("returned profile aliases stored limitations")
	}
}
