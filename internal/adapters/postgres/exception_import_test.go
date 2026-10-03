package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresExceptionImportPreservesExistingHistoryAndRejectsMismatches(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 123456000, time.UTC)
	if err := store.ApplyCriticalMutation(t.Context(), app.CriticalMutation{Tenants: []domain.Tenant{{ID: "tenant", Name: "Tenant", CreatedAt: now}, {ID: "other", Name: "Other", CreatedAt: now}}}); err != nil {
		t.Fatal(err)
	}
	v := domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "release", FindingID: "finding", ControlID: "control", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), Approved: true, ApprovedBy: "reviewer", ApprovedAt: &now, CreatedAt: now}
	write := func(v domain.Exception) error {
		return store.SaveRelationalState(t.Context(), app.PersistedState{Exceptions: map[string]domain.Exception{v.ID: v}})
	}
	if err := write(v); err != nil {
		t.Fatal("initial legacy import rejected", err)
	}
	raw := func() string {
		t.Helper()
		var row string
		if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(e)::text FROM exceptions e WHERE id='exception'`).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	before := raw()
	stale := v
	stale.Approved = false
	stale.ApprovedBy = ""
	stale.ApprovedAt = nil
	stale.CreatedAt = time.Time{}
	for _, safe := range []domain.Exception{v, v, stale} {
		if err := write(safe); err != nil || raw() != before {
			t.Fatal("safe replay modified historical exception", err)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*domain.Exception)
	}{
		{"tenant", func(v *domain.Exception) { v.TenantID = "other" }},
		{"release", func(v *domain.Exception) { v.ReleaseID = "other" }},
		{"finding", func(v *domain.Exception) { v.FindingID = "other" }},
		{"control", func(v *domain.Exception) { v.ControlID = "other" }},
		{"owner", func(v *domain.Exception) { v.Owner = "Other" }},
		{"reason", func(v *domain.Exception) { v.Reason = "Changed" }},
		{"expiry", func(v *domain.Exception) { v.ExpiresAt = v.ExpiresAt.Add(time.Hour) }},
		{"creation", func(v *domain.Exception) { v.CreatedAt = v.CreatedAt.Add(time.Hour) }},
		{"approval actor", func(v *domain.Exception) { v.ApprovedBy = "other" }},
		{"approval time", func(v *domain.Exception) { later := now.Add(time.Minute); v.ApprovedAt = &later }},
		{"inconsistent approval", func(v *domain.Exception) { v.Approved = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := v
			test.change(&changed)
			err := write(changed)
			rejected := errors.Is(err, app.ErrConflict) || test.name == "tenant" && errors.Is(err, app.ErrNotFound)
			if !rejected || raw() != before {
				t.Fatal("historical mismatch accepted or changed row", err)
			}
		})
	}
	changed := v
	changed.Reason = "Changed"
	err := store.SaveRelationalState(t.Context(), app.PersistedState{Tenants: map[string]domain.Tenant{"tenant": {ID: "tenant", Name: "Changed", CreatedAt: now}}, Exceptions: map[string]domain.Exception{v.ID: changed}})
	var name string
	if readErr := store.pool.QueryRow(t.Context(), `SELECT name FROM tenants WHERE id='tenant'`).Scan(&name); !errors.Is(err, app.ErrConflict) || readErr != nil || name != "Tenant" || raw() != before {
		t.Fatal("failed replay partially committed earlier writes", err, readErr, name)
	}
	// Existing pending records cannot gain approval through bulk import.
	pending := stale
	pending.ID = "pending"
	pending.CreatedAt = now
	if err := write(pending); err != nil {
		t.Fatal(err)
	}
	pending.Approved = true
	pending.ApprovedBy = "reviewer"
	pending.ApprovedAt = &now
	if err := write(pending); !errors.Is(err, app.ErrConflict) {
		t.Fatal("bulk replay created a new approval", err)
	}
}
