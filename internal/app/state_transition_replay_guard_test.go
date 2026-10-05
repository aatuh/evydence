package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLocalStateTransitionGuardsCheckOwnershipAndGrantsNotLifecycle(t *testing.T) {
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
	c, err := l.CreateReleaseCandidate(t.Context(), a, CreateReleaseCandidateInput{ReleaseID: r.ID, Name: "Snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("state guard used clock") }
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeReleaseWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: r.ID, Scopes: []string{ScopeReleaseWrite}}}}
	checks := []func(domain.Actor) error{func(a domain.Actor) error { return l.AuthorizeReleaseTransition(t.Context(), a, r.ID) }, func(a domain.Actor) error { return l.AuthorizeCandidateTransition(t.Context(), a, c.ID) }}
	for _, check := range checks {
		if err := check(human); err != nil {
			t.Fatal(err)
		}
	}
	human.ResourceGrants = nil
	for _, check := range checks {
		if err := check(human); !errors.Is(err, ErrForbidden) {
			t.Fatal("removed grant retained transition replay", err)
		}
	}
	changed := r
	changed.State = "invalid"
	changed.Version = "private"
	changed.Revision = 0
	l.releases[r.ID] = changed
	changedC := c
	changedC.State = "invalid"
	changedC.Revision = 0
	changedC.SnapshotHash = "invalid"
	l.candidates[c.ID] = changedC
	for _, check := range checks {
		if err := check(a); err != nil {
			t.Fatal("historical guard reread lifecycle", err)
		}
	}
	changed.TenantID = "other"
	l.releases[r.ID] = changed
	for _, check := range checks {
		if err := check(a); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign parent retained replay", err)
		}
	}
	if len(l.chain[a.TenantID]) != audits {
		t.Fatal("guard wrote audit")
	}
}
