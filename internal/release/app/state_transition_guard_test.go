package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type stateTransitionGuardFake struct {
	release       ReleaseTransitionScope
	candidate     CandidateTransitionScope
	reads, grants int
	denied        bool
}

func (f *stateTransitionGuardFake) ExecuteReleaseState(ctx context.Context, fn func(context.Context, ReleaseStateTransaction) error) error {
	return fn(ctx, f)
}
func (f *stateTransitionGuardFake) ExecuteCandidateState(ctx context.Context, fn func(context.Context, CandidateStateTransaction) error) error {
	return fn(ctx, f)
}
func (f *stateTransitionGuardFake) ReadReleaseTransitionScope(context.Context, string, string) (ReleaseTransitionScope, error) {
	f.reads++
	return f.release, nil
}
func (f *stateTransitionGuardFake) ReadCandidateTransitionScope(context.Context, string, string) (CandidateTransitionScope, error) {
	f.reads++
	return f.candidate, nil
}
func (f *stateTransitionGuardFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.ScopeOnly {
		return nil
	}
	f.grants++
	if f.denied {
		return application.ErrForbidden
	}
	return nil
}
func (*stateTransitionGuardFake) ReadReleaseState(context.Context, string, string) (releasedomain.Release, error) {
	panic("guard read release version/state/revision")
}
func (*stateTransitionGuardFake) ReadProductCoordinates(context.Context, string, string) (ProductCoordinates, error) {
	panic("guard read product slug")
}
func (*stateTransitionGuardFake) ReadCandidateState(context.Context, string, string) (CandidateStateRow, error) {
	panic("guard read candidate document/state/revision")
}
func (*stateTransitionGuardFake) UpdateRelease(context.Context, releasedomain.Release, int64, string) error {
	panic("guard updated release")
}
func (*stateTransitionGuardFake) UpdateCandidateState(context.Context, releasedomain.ReleaseCandidate, int64, string) error {
	panic("guard updated candidate")
}
func (*stateTransitionGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard appended audit")
}

func TestStateTransitionGuardsNeverReadLifecycleOrMetadataOrGenerateEffects(t *testing.T) {
	f := &stateTransitionGuardFake{release: ReleaseTransitionScope{ID: "release", TenantID: "tenant", ProductID: "product"}, candidate: CandidateTransitionScope{ID: "candidate", TenantID: "tenant", ReleaseID: "release", ProductID: "product"}}
	clock := application.ClockFunc(func() time.Time { panic("guard used clock") })
	ids := application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })
	r, err := NewReleaseStateCommands(ReleaseStateCommandConfig{Reader: f, Authorizer: f, Transactions: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: f, Transactions: f, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{ScopeReleaseWrite}}
	checks := []func(context.Context) error{func(ctx context.Context) error { return r.AuthorizeReleaseTransition(ctx, a, " release ") }, func(ctx context.Context) error { return c.AuthorizeCandidateTransition(ctx, a, " candidate ") }}
	for _, check := range checks {
		if err := check(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if f.reads != 2 || f.grants != 2 {
		t.Fatal("guard omitted ownership/grants", f)
	}
	f.denied = true
	for _, check := range checks {
		if err := check(t.Context()); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("removed grant retained replay", err)
		}
	}
	f.denied = false
	f.release.TenantID, f.candidate.TenantID = "other", "other"
	for _, check := range checks {
		if err := check(t.Context()); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign coordinates retained replay", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := f.reads
	for _, check := range checks {
		if err := check(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("guard lost cancellation", err)
		}
	}
	if f.reads != before {
		t.Fatal("cancelled guard opened reads")
	}
}
