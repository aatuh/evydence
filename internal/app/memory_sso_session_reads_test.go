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

func TestMemorySSOSessionReadersSeparateIssuanceEligibilityFromRevocationMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		at := fixedNow()
		tx.state.SSOProviders[tenant+"-provider"] = domain.SSOProvider{ID: tenant + "-provider", TenantID: tenant, Status: "inactive", JWKS: map[string]any{"irrelevant": make(chan int)}}
		tx.state.SSOSessions[tenant+"-session"] = domain.SSOSession{ID: tenant + "-session", TenantID: tenant, UserID: tenant + "-user", ProviderID: tenant + "-provider", Prefix: "public-prefix", Hash: "private-session-hash", Groups: []string{"reviewers"}, ExpiresAt: at.Add(-1), RevokedAt: &at, SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: at}
	}
	issuance, ok := tx.Repositories().Identity.(identityapp.SSOSessionWriteReader)
	if !ok {
		t.Fatal("memory identity lacks focused session issuance reads")
	}
	revocation, ok := tx.Repositories().Identity.(identityapp.SSOSessionRevocationReader)
	if !ok {
		t.Fatal("memory identity lacks focused session revocation reads")
	}
	if err := issuance.LockSSOSessionWrites(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if err := issuance.ValidateSSOSessionTargets(t.Context(), "tenant", "tenant-user", "tenant-provider"); !errors.Is(err, ErrNotFound) {
		t.Fatal("issuance accepted inactive user", err)
	}
	user := tx.state.Users["tenant-user"]
	user.Status = "active"
	user.DisplayName = strings.Repeat("private", 10000)
	user.OrganizationID = "foreign-org"
	tx.state.Users[user.ID] = user
	if err := issuance.ValidateSSOSessionTargets(t.Context(), "tenant", user.ID, "tenant-provider"); err != nil {
		t.Fatal("issuance read irrelevant user/provider metadata or denied provider-existence compatibility", err)
	}
	for _, targets := range []struct{ user, provider string }{{"foreign-user", "tenant-provider"}, {user.ID, "foreign-provider"}, {"missing", "tenant-provider"}, {user.ID, "missing"}} {
		if err := issuance.ValidateSSOSessionTargets(t.Context(), "tenant", targets.user, targets.provider); !errors.Is(err, ErrNotFound) {
			t.Fatal("issuance accepted foreign/missing parent", targets, err)
		}
	}
	stored := tx.state.SSOSessions["tenant-session"]
	got, err := revocation.ReadSSOSessionForRevocation(t.Context(), "tenant", stored.ID)
	want := identitydomain.SSOSession{ID: stored.ID, TenantID: stored.TenantID, UserID: stored.UserID, ProviderID: stored.ProviderID, Prefix: stored.Prefix, Groups: []string{"reviewers"}, ExpiresAt: stored.ExpiresAt, RevokedAt: stored.RevokedAt, SchemaVersion: stored.SchemaVersion, CreatedAt: stored.CreatedAt}
	if err != nil || !reflect.DeepEqual(got, want) || got.Hash != "" {
		t.Fatal("revocation metadata changed or disclosed hash", got, err)
	}
	got.Groups[0] = "modified"
	*got.RevokedAt = got.RevokedAt.AddDate(1, 0, 0)
	if !reflect.DeepEqual(stored, tx.state.SSOSessions[stored.ID]) {
		t.Fatal("revocation read or metadata mutation changed stored session")
	}
	delete(tx.state.Users, user.ID)
	delete(tx.state.SSOProviders, "tenant-provider")
	if got, err := revocation.ReadSSOSessionForRevocation(t.Context(), "tenant", stored.ID); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("expired/revoked metadata depended on missing login parents", got, err)
	}
	for _, id := range []string{"foreign-session", "missing"} {
		if _, err := revocation.ReadSSOSessionForRevocation(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/missing session accepted", id, err)
		}
	}
	bad := stored
	bad.Prefix = strings.Repeat("x", 1025)
	tx.state.SSOSessions[bad.ID] = bad
	if _, err := revocation.ReadSSOSessionForRevocation(t.Context(), "tenant", bad.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized session metadata was truncated or accepted", err)
	}
	bad = stored
	bad.Groups = []string{strings.Repeat("x", 131073)}
	tx.state.SSOSessions[bad.ID] = bad
	if _, err := revocation.ReadSSOSessionForRevocation(t.Context(), "tenant", bad.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized session groups accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := revocation.ReadSSOSessionForRevocation(ctx, "tenant", stored.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("session metadata ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := issuance.LockSSOSessionWrites(t.Context(), "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("session reader retained closed transaction", err)
	}
}
