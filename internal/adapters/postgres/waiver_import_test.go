package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresWaiverImportPreservesExistingHistoryAndRejectsMismatches(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 123456000, time.UTC)
	if err := store.ApplyCriticalMutation(t.Context(), app.CriticalMutation{Tenants: []domain.Tenant{{ID: "tenant", Name: "Tenant", CreatedAt: now}, {ID: "other", Name: "Other", CreatedAt: now}}}); err != nil {
		t.Fatal(err)
	}
	v := domain.Waiver{ID: "waiver", TenantID: "tenant", ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), Approved: true, ApprovedBy: "reviewer", ApprovedAt: &now, Supersedes: "legacy-prior", SupersededBy: "legacy-next", SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now}
	write := func(v domain.Waiver) error {
		return store.SaveRelationalState(t.Context(), app.PersistedState{Waivers: map[string]domain.Waiver{v.ID: v}})
	}
	if err := write(v); err != nil {
		t.Fatal("legacy initial import rejected", err)
	}
	raw := func() string {
		t.Helper()
		var row string
		if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM waivers w WHERE id='waiver'`).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	before := raw()
	stale := v
	stale.Approved = false
	stale.ApprovedBy = ""
	stale.ApprovedAt = nil
	stale.SupersededBy = ""
	stale.CreatedAt = time.Time{}
	for _, safe := range []domain.Waiver{v, v, stale} {
		if err := write(safe); err != nil || raw() != before {
			t.Fatal("safe replay changed historical waiver", err)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*domain.Waiver)
	}{
		{"tenant", func(v *domain.Waiver) { v.TenantID = "other" }},
		{"scope type", func(v *domain.Waiver) { v.ScopeType = "control" }},
		{"scope id", func(v *domain.Waiver) { v.ScopeID = "other" }},
		{"control", func(v *domain.Waiver) { v.ControlID = "other" }},
		{"policy", func(v *domain.Waiver) { v.PolicyID = "other" }},
		{"owner", func(v *domain.Waiver) { v.Owner = "Other" }},
		{"risk", func(v *domain.Waiver) { v.Risk = "high" }},
		{"reason", func(v *domain.Waiver) { v.Reason = "Changed" }},
		{"expiry", func(v *domain.Waiver) { v.ExpiresAt = v.ExpiresAt.Add(time.Hour) }},
		{"approval actor", func(v *domain.Waiver) { v.ApprovedBy = "other" }},
		{"approval time", func(v *domain.Waiver) { later := v.ApprovedAt.Add(time.Hour); v.ApprovedAt = &later }},
		{"inconsistent approval", func(v *domain.Waiver) { v.Approved = false }},
		{"supersedes", func(v *domain.Waiver) { v.Supersedes = "other" }},
		{"superseded by", func(v *domain.Waiver) { v.SupersededBy = "other" }},
		{"schema", func(v *domain.Waiver) { v.SchemaVersion = "other.v1" }},
		{"creation", func(v *domain.Waiver) { v.CreatedAt = v.CreatedAt.Add(time.Hour) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := v
			test.change(&changed)
			err := write(changed)
			rejected := errors.Is(err, app.ErrConflict) || test.name == "tenant" && errors.Is(err, app.ErrNotFound)
			if !rejected {
				t.Fatal("historical mismatch accepted", err)
			}
			if raw() != before {
				t.Fatal("rejected replay modified existing history")
			}
		})
	}
	// Later row validation must roll back earlier relational writes as well.
	changed := v
	changed.Reason = "Changed"
	err := store.SaveRelationalState(t.Context(), app.PersistedState{Tenants: map[string]domain.Tenant{"tenant": {ID: "tenant", Name: "Changed", CreatedAt: now}}, Waivers: map[string]domain.Waiver{v.ID: changed}})
	var tenantName string
	if queryErr := store.pool.QueryRow(t.Context(), `SELECT name FROM tenants WHERE id='tenant'`).Scan(&tenantName); !errors.Is(err, app.ErrConflict) || queryErr != nil || tenantName != "Tenant" || raw() != before {
		t.Fatal("failed replay partially committed unrelated rows", err, queryErr, tenantName)
	}
}
