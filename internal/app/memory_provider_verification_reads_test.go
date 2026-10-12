package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemoryProviderVerificationLinkReaderUsesBoundedOwnedRowsWithoutUserGrants(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.SSOProviders[tenant+"-provider"] = domain.SSOProvider{ID: tenant + "-provider", TenantID: tenant, Name: "Provider", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", Status: "inactive", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: fixedNow()}
		tx.state.IdentityLinks[tenant+"-link"] = domain.UserIdentityLink{ID: tenant + "-link", TenantID: tenant, UserID: tenant + "-user", ProviderID: tenant + "-provider", Subject: "subject", Email: "identity@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: fixedNow()}
		u := tx.state.Users[tenant+"-user"]
		u.DisplayName = strings.Repeat("private", 10000)
		tx.state.Users[u.ID] = u
	}
	r, ok := tx.Repositories().Identity.(identityapp.ProviderVerificationReader)
	if !ok {
		t.Fatal("memory identity lacks native provider receipt reader")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := r.IdentityLink(t.Context(), "tenant", "tenant-provider", "subject")
	if err != nil || !found || got != identitydomain.UserIdentityLink(before.IdentityLinks["tenant-link"]) {
		t.Fatal("link projection lost bounded fields", got, found, err)
	}
	got.Email = "changed"
	for _, query := range [][3]string{{"tenant", "foreign-provider", "subject"}, {"foreign", "tenant-provider", "subject"}, {"tenant", "tenant-provider", "absent"}} {
		got, found, err := r.IdentityLink(t.Context(), query[0], query[1], query[2])
		if err != nil || found || got != (identitydomain.UserIdentityLink{}) {
			t.Fatal("link query crossed tenant/provider/subject tuple", got, found, err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("link read mutated trust, users or roles")
	}
	p, err := r.ReadOwnedSSOProvider(t.Context(), "tenant", "tenant-provider")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SSOExchangeSnapshot{Provider: domain.SSOProvider(p), Subject: "appearing-link"}
	if err := tx.Repositories().Identity.ValidateSSOExchangeState(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	tx.state.IdentityLinks["appearing-link"] = domain.UserIdentityLink{ID: "appearing-link", TenantID: "tenant", ProviderID: p.ID, UserID: "tenant-user", Subject: "appearing-link", SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: fixedNow()}
	if err := tx.Repositories().Identity.ValidateSSOExchangeState(t.Context(), snapshot); !errors.Is(err, ErrConflict) {
		t.Fatal("absent link appearance bypassed snapshot check", err)
	}
	link := tx.state.IdentityLinks["tenant-link"]
	link.Email = strings.Repeat("x", 65537)
	tx.state.IdentityLinks[link.ID] = link
	if got, found, err := r.IdentityLink(t.Context(), "tenant", p.ID, "subject"); !errors.Is(err, ErrConflict) || found || got != (identitydomain.UserIdentityLink{}) {
		t.Fatal("oversized selected link escaped", got, found, err)
	}
	tx.state.IdentityLinks["tenant-link"] = before.IdentityLinks["tenant-link"]
	duplicate := before.IdentityLinks["tenant-link"]
	duplicate.ID = "duplicate-link"
	tx.state.IdentityLinks[duplicate.ID] = duplicate
	if got, found, err := r.IdentityLink(t.Context(), "tenant", p.ID, "subject"); !errors.Is(err, ErrConflict) || found || got != (identitydomain.UserIdentityLink{}) {
		t.Fatal("ambiguous link tuple granted nondeterministic identity", got, found, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := r.IdentityLink(ctx, "tenant", p.ID, "subject"); !errors.Is(err, context.Canceled) {
		t.Fatal("link reader ignored cancellation", err)
	}
	if _, _, err := r.IdentityLink(t.Context(), "tenant", p.ID, strings.Repeat("x", 65537)); !errors.Is(err, ErrValidation) {
		t.Fatal("oversized query accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.IdentityLink(t.Context(), "tenant", p.ID, "subject"); !errors.Is(err, ErrConflict) {
		t.Fatal("link reader used closed transaction", err)
	}
}
