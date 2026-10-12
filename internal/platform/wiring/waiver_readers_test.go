package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresWaiverReadersBoundRecordsAndResolveCurrentScopes(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedApprovalSubjects(t, ctx, store, pool)
	err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Governance.(riskapp.WaiverCommandReader)
		if !ok {
			t.Fatal("bounded waiver reader missing")
		}
		for _, subject := range []struct{ kind, id string }{{"release", "release"}, {"finding", "finding"}, {"control", "control"}, {"policy", "policy"}} {
			v, err := r.ReadWaiverSubject(ctx, "tenant", subject.kind, subject.id)
			if err != nil || v.ID != subject.id || v.Type != subject.kind || v.TenantID != "tenant" {
				t.Fatal("current subject resolution failed", subject, v, err)
			}
			if (subject.kind == "release" || subject.kind == "finding") && (v.ProductID != "product" || v.ReleaseID != "release") {
				t.Fatal("subject lost ownership", v)
			}
			if _, err := r.ReadWaiverSubject(ctx, "other", subject.kind, subject.id); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("foreign waiver subject exposed", err)
			}
		}
		state, err := r.ReadWaiverTransitionState(ctx, "tenant", "waiver")
		if err != nil || state.ID != "waiver" || state.TenantID != "tenant" || state.ScopeType != "release" || state.ScopeID != "release" || state.Approved || state.ExpiresAt.IsZero() {
			t.Fatal("bounded metadata unavailable for oversized historical record", state, err)
		}
		if _, err := r.ReadWaiverForApproval(ctx, "tenant", "waiver"); !errors.Is(err, app.ErrValidation) {
			t.Fatal("oversized reason transferred", err)
		}
		if _, err := r.ReadWaiverTransitionState(ctx, "other", "waiver"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign waiver state exposed", err)
		}
		if _, err := r.ReadWaiverForApproval(ctx, "other", "waiver"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign waiver record exposed", err)
		}
		if _, err := r.ReadWaiverSubject(ctx, "tenant", "waiver", "waiver"); !errors.Is(err, app.ErrValidation) {
			t.Fatal("recursive scope accepted", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE waivers SET reason='Reviewed',schema_version='waiver.v1.0.0' WHERE id='waiver'`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		r := repos.Governance.(riskapp.WaiverCommandReader)
		v, err := r.ReadWaiverForApproval(ctx, "tenant", "waiver")
		if err != nil || v.Reason != "Reviewed" || v.Owner != "Owner" || v.ScopeID != "release" || v.Approved || v.ApprovedAt != nil || v.SchemaVersion != "waiver.v1.0.0" {
			t.Fatal("bounded full record changed", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
