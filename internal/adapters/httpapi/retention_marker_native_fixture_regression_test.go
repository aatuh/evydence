package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestRetentionMarkerNativeFixtureUsesCurrentRootsClockAndAtomicHumanAudit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	project, err := ledger.CreateProject(t.Context(), owner.actor, owner.product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("retention marker used aggregate clock") }})
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"admin"}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var created []operationsdomain.LegalHold
	for _, root := range []struct{ kind, id string }{{"tenant", human.TenantID}, {"product", owner.product.ID}, {"project", project.ID}, {"release", owner.release.ID}, {"evidence", owner.evidence.ID}} {
		if err := f.AuthorizeRetentionMarker(t.Context(), human, root.kind, root.id); err != nil || clock.calls != len(created) {
			t.Fatal("retention preflight used stale state/time/effects", err)
		}
		v, err := f.CreateLegalHold(t.Context(), human, operationsapp.RetentionMarkerInput{ScopeType: root.kind, ScopeID: root.id, Reason: " Review ", Owner: " Legal "})
		if err != nil || v.ID == "" || v.TenantID != human.TenantID || v.ScopeType != root.kind || v.ScopeID != root.id || v.Reason != "Review" || v.Owner != "Legal" || v.ReleasedAt != nil || v.SchemaVersion != operationsdomain.LegalHoldSchemaVersion || v.CreatedAt != clock.at {
			t.Fatal("legal hold lost full DTO/current root/explicit time", err)
		}
		created = append(created, v)
	}
	input := operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: "evidence", ScopeID: owner.evidence.ID, Reason: " Extend ", Owner: " Security "}, RetentionUntil: clock.at.Add(time.Hour)}
	v, err := f.CreateRetentionOverride(t.Context(), human, input)
	if err != nil || v.ID == "" || v.TenantID != human.TenantID || v.ScopeType != input.ScopeType || v.ScopeID != input.ScopeID || v.Reason != "Extend" || v.Owner != "Security" || v.RetentionUntil != input.RetentionUntil || v.SchemaVersion != operationsdomain.RetentionOverrideSchemaVersion || v.CreatedAt != clock.at || clock.calls != 6 {
		t.Fatal("retention override lost full DTO/current root/time", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.LegalHolds) != len(before.LegalHolds)+5 || len(after.RetentionOverrides) != len(before.RetentionOverrides)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+6 {
		t.Fatal("marker and audit effects did not commit together", err)
	}
	for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.OccurredAt != clock.at {
			t.Fatal("retention human audit attribution/time lost")
		}
	}
	if !reflect.DeepEqual(before.OutboxJobs, after.OutboxJobs) {
		t.Fatal("retention markers queued unrelated work")
	}
	repeatedHold, err := f.CreateLegalHold(t.Context(), human, input.RetentionMarkerInput)
	if err != nil || repeatedHold.ID == created[len(created)-1].ID {
		t.Fatal("repeated hold mutated or reused historical marker", err)
	}
	repeatedOverride, err := f.CreateRetentionOverride(t.Context(), human, input)
	if err != nil || repeatedOverride.ID == v.ID {
		t.Fatal("repeated override mutated or reused historical marker", err)
	}
	repeated, err := base.Snapshot()
	if err != nil || len(repeated.LegalHolds) != len(after.LegalHolds)+1 || len(repeated.RetentionOverrides) != len(after.RetentionOverrides)+1 || len(repeated.AuditEntries[human.TenantID]) != len(after.AuditEntries[human.TenantID])+2 || !reflect.DeepEqual(repeated.RetentionOverrides[v.ID], after.RetentionOverrides[v.ID]) || !reflect.DeepEqual(repeated.LegalHolds[created[0].ID], after.LegalHolds[created[0].ID]) {
		t.Fatal("repeated creation did not append while preserving old markers", err)
	}
	after = repeated
	factory.fail = true
	if hold, err := f.CreateLegalHold(t.Context(), human, input.RetentionMarkerInput); err == nil || hold != (operationsdomain.LegalHold{}) {
		t.Fatal("failed commit exposed legal hold", err)
	}
	if override, err := f.CreateRetentionOverride(t.Context(), human, input); err == nil || override != (operationsdomain.RetentionOverride{}) {
		t.Fatal("failed commit exposed override", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed marker writes published partial state", err)
	}
	clock.at = input.RetentionUntil.Add(time.Hour)
	if err := f.AuthorizeRetentionMarker(t.Context(), human, input.ScopeType, input.ScopeID); err != nil {
		t.Fatal("historical override authority expired with wall time", err)
	}
	if _, err := f.CreateRetentionOverride(t.Context(), human, input); !errors.Is(err, app.ErrValidation) {
		t.Fatal("new expired override accepted", err)
	}
}

func TestRetentionMarkerNativeFixtureDeniesForeignAndScopedAdminWithoutEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	foreignProject, err := ledger.CreateProject(t.Context(), foreign.actor, foreign.product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base})}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []struct{ kind, id string }{{"tenant", foreign.actor.TenantID}, {"product", foreign.product.ID}, {"project", foreignProject.ID}, {"release", foreign.release.ID}, {"evidence", foreign.evidence.ID}, {"evidence", "missing"}} {
		if err := f.AuthorizeRetentionMarker(t.Context(), owner.actor, root.kind, root.id); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign/missing marker root accepted", err)
		}
		in := operationsapp.RetentionMarkerInput{ScopeType: root.kind, ScopeID: root.id, Reason: "Review", Owner: "Legal"}
		if v, err := f.CreateLegalHold(t.Context(), owner.actor, in); !errors.Is(err, app.ErrNotFound) || v != (operationsdomain.LegalHold{}) {
			t.Fatal("foreign marker root wrote hold", err)
		}
		if v, err := f.CreateRetentionOverride(t.Context(), owner.actor, operationsapp.RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: time.Now().Add(time.Hour)}); !errors.Is(err, app.ErrNotFound) || v != (operationsdomain.RetentionOverride{}) {
			t.Fatal("foreign marker root wrote override", err)
		}
	}
	in := operationsapp.RetentionMarkerInput{ScopeType: "product", ScopeID: owner.product.ID, Reason: "Review", Owner: "Legal"}
	scoped := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"admin"}}}}
	for _, a := range []domain.Actor{scoped, {TenantID: scoped.TenantID, UserID: scoped.UserID, Scopes: scoped.Scopes}} {
		if err := f.AuthorizeRetentionMarker(t.Context(), a, in.ScopeType, in.ScopeID); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("scoped/revoked admin preflight accepted", err)
		}
		if _, err := f.CreateLegalHold(t.Context(), a, in); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("scoped/revoked admin wrote hold", err)
		}
		if _, err := f.CreateRetentionOverride(t.Context(), a, operationsapp.RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: time.Now().Add(time.Hour)}); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("scoped/revoked admin wrote override", err)
		}
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("marker denial changed repository state", err)
	}
}

func TestRetentionMarkerNativeFixtureRequiresRepositoriesAndPreservesExplicitClock(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	in := operationsapp.RetentionMarkerInput{ScopeType: "tenant", ScopeID: a.TenantID, Reason: "Review", Owner: "Legal"}
	if _, err := f.CreateLegalHold(t.Context(), a, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored cached hold creation", err)
	}
	if _, err := f.CreateRetentionOverride(t.Context(), a, operationsapp.RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: time.Now().Add(time.Hour)}); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored cached override creation", err)
	}
	var missingContext context.Context
	if _, err := f.CreateLegalHold(missingContext, a, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil marker context accepted", err)
	}
	if _, err := f.CreateRetentionOverride(missingContext, a, operationsapp.RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: time.Now().Add(time.Hour)}); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil override context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateLegalHold(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal("marker cancellation lost", err)
	}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	explicit := &markerHTTPFake{}
	server := &Server{retentionMarkerCommands: operationsFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock}}
	other := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	server.bindOperationsFixtureCommands(other)
	bound, ok := server.retentionMarkerCommands.(operationsFixtureCommands)
	if !ok || bound.ledger != other || bound.clock != clock {
		t.Fatal("marker rebind discarded explicit clock")
	}
	server.retentionMarkerCommands = explicit
	server.bindOperationsFixtureCommands(other)
	if server.retentionMarkerCommands != explicit {
		t.Fatal("marker rebind replaced injected command")
	}
}
