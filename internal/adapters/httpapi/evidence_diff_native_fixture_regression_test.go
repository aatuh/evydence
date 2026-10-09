package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type diffFixtureClock struct {
	at    time.Time
	calls int
}

func (c *diffFixtureClock) Now() time.Time { c.calls++; return c.at }

func TestDiffNativeFixtureUsesCurrentSubjectsExplicitClockAndAtomicDetachedEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	target, err := ledger.UploadSBOM(t.Context(), owner.actor, owner.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one","purl":"pkg:generic/one@1"},{"type":"library","name":"next","purl":"pkg:generic/next@2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := ledger.UploadOpenAPIContract(t.Context(), owner.actor, owner.product.ID, owner.release.ID, "2", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("diff used aggregate clock") }})
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)}
	f := ingestionDiffFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceRead}}}}
	sbomInput := evidenceapp.CreateSBOMDiffInput{BaseSBOMID: owner.sbom.ID, TargetSBOMID: target.ID, ReleaseID: owner.release.ID}
	contractInput := evidenceapp.CreateContractDiffInput{BaseContractID: owner.contract.ID, TargetContractID: contract.ID, ReleaseID: owner.release.ID}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateSBOMDiff(t.Context(), human, sbomInput); err != nil {
		t.Fatal("current SBOM preflight rejected", err)
	}
	if err := f.AuthorizeCreateContractDiff(t.Context(), human, contractInput); err != nil {
		t.Fatal("current contract preflight rejected", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 0 {
		t.Fatal("preflight allocated time or wrote", err)
	}
	diff, err := f.CreateSBOMDiff(t.Context(), human, sbomInput)
	if err != nil {
		t.Fatal(err)
	}
	if diff.ID == "" || len(diff.DependencyChanges) != 2 {
		t.Fatal("missing diff/change identities", diff)
	}
	added := evidencedomain.SBOMComponent{Identity: "purl:pkg:generic/next@2", Name: "next", PURL: "pkg:generic/next@2"}
	removed := evidencedomain.SBOMComponent{Identity: "purl:pkg:generic/two@1", Name: "two", PURL: "pkg:generic/two@1"}
	want := evidencedomain.SBOMDiff{ID: diff.ID, TenantID: human.TenantID, BaseSBOMID: owner.sbom.ID, TargetSBOMID: target.ID, ReleaseID: owner.release.ID, AddedComponents: []evidencedomain.SBOMComponent{added}, RemovedComponents: []evidencedomain.SBOMComponent{removed}, UnchangedCount: 1, SchemaVersion: evidencedomain.SBOMDiffSchemaVersion, CreatedAt: clock.at, DependencyChanges: []evidencedomain.DependencyChange{{ID: diff.DependencyChanges[0].ID, TenantID: human.TenantID, SBOMDiffID: diff.ID, ChangeType: "added", Component: added, SchemaVersion: evidencedomain.DependencyChangeSchemaVersion, CreatedAt: clock.at}, {ID: diff.DependencyChanges[1].ID, TenantID: human.TenantID, SBOMDiffID: diff.ID, ChangeType: "removed", Component: removed, SchemaVersion: evidencedomain.DependencyChangeSchemaVersion, CreatedAt: clock.at}}}
	if !reflect.DeepEqual(diff, want) {
		t.Fatal("SBOM diff lost complete deterministic fields", diff, want)
	}
	cdiff, err := f.CreateContractDiff(t.Context(), human, contractInput)
	if err != nil {
		t.Fatal(err)
	}
	cwant := evidencedomain.ContractDiff{ID: cdiff.ID, TenantID: human.TenantID, BaseContractID: owner.contract.ID, TargetContractID: contract.ID, ProductID: owner.product.ID, ReleaseID: owner.release.ID, Result: "breaking", BreakingChanges: []string{"target contract has fewer paths than base contract"}, SchemaVersion: evidencedomain.ContractDiffSchemaVersion, CreatedAt: clock.at}
	if cdiff.ID == "" || !reflect.DeepEqual(cdiff, cwant) {
		t.Fatal("contract diff lost complete deterministic fields", cdiff, cwant)
	}
	diff.AddedComponents[0].Name, diff.DependencyChanges[0].Component.Name, cdiff.BreakingChanges[0] = "mutated", "mutated", "mutated"
	after, err = base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.SBOMDiffs[want.ID], domain.SBOMDiffFromContext(want)) || !reflect.DeepEqual(after.ContractDiffs[cwant.ID], domain.ContractDiffFromContext(cwant)) {
		t.Fatal("diff results alias repository or differ from DTO")
	}
	if len(after.SBOMDiffs) != len(before.SBOMDiffs)+1 || len(after.ContractDiffs) != len(before.ContractDiffs)+1 || len(after.DependencyChanges) != len(before.DependencyChanges)+2 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs) || len(after.Evidence) != len(before.Evidence) {
		t.Fatal("diff effects incomplete or unrelated effects published")
	}
	for _, a := range after.AuditEntries[human.TenantID] {
		if a.SubjectID == want.ID || a.SubjectID == cwant.ID {
			if a.ActorID != human.UserID || a.ActorType != "human_user" || a.OccurredAt != clock.at {
				t.Fatal("diff audit lost caller/time")
			}
		}
	}
	before = after
	factory.fail = true
	if got, err := f.CreateSBOMDiff(t.Context(), human, sbomInput); err == nil || !reflect.DeepEqual(got, evidencedomain.SBOMDiff{}) {
		t.Fatal("failed commit returned SBOM result", err)
	}
	if got, err := f.CreateContractDiff(t.Context(), human, contractInput); err == nil || !reflect.DeepEqual(got, evidencedomain.ContractDiff{}) {
		t.Fatal("failed commit returned contract result", err)
	}
	after, err = base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed diff commit published effects", err)
	}
}

func TestDiffNativeFixtureRejectsForeignScopesRevokedGrantsAndPreservesRebindDependencies(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceReadFixtureScope(t, ledger, "Foreign")
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)}
	f := ingestionDiffFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceRead}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	si := evidenceapp.CreateSBOMDiffInput{BaseSBOMID: owner.sbom.ID, TargetSBOMID: foreign.sbom.ID, ReleaseID: owner.release.ID}
	ci := evidenceapp.CreateContractDiffInput{BaseContractID: owner.contract.ID, TargetContractID: foreign.contract.ID, ReleaseID: owner.release.ID}
	if err := f.AuthorizeCreateSBOMDiff(t.Context(), human, si); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("foreign SBOM preflight", err)
	}
	if v, err := f.CreateSBOMDiff(t.Context(), human, si); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.SBOMDiff{}) {
		t.Fatal("foreign SBOM write", err)
	}
	if err := f.AuthorizeCreateContractDiff(t.Context(), human, ci); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("foreign contract preflight", err)
	}
	if v, err := f.CreateContractDiff(t.Context(), human, ci); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.ContractDiff{}) {
		t.Fatal("foreign contract write", err)
	}
	human.ResourceGrants = nil
	if err := f.AuthorizeCreateSBOMDiff(t.Context(), human, si); !errors.Is(err, evidenceapp.ErrForbidden) {
		t.Fatal("revoked grant preflight", err)
	}
	if v, err := f.CreateContractDiff(t.Context(), human, ci); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, evidencedomain.ContractDiff{}) {
		t.Fatal("revoked grant write", err)
	}
	var nilCtx context.Context // Deliberately test rejection of the zero context.
	if v, err := f.CreateSBOMDiff(nilCtx, owner.actor, si); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.SBOMDiff{}) {
		t.Fatal("nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateContractDiff(ctx, owner.actor, ci); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 0 {
		t.Fatal("denied diff generated effects/time", err)
	}
	s := &Server{sbomDiffCommands: f, contractDiffCommands: f}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base})
	s.bindDiffFixturePorts(rebound)
	for _, port := range []any{s.sbomDiffCommands, s.contractDiffCommands} {
		bound, ok := port.(ingestionDiffFixture)
		if !ok || bound.ledger != rebound || bound.clock != clock {
			t.Fatal("diff rebind discarded dependency")
		}
	}
	explicitSBOM, explicitContract := &sbomDiffHTTPFake{}, &contractDiffHTTPFake{}
	s.sbomDiffCommands, s.contractDiffCommands = explicitSBOM, explicitContract
	s.bindDiffFixturePorts(ledger)
	if s.sbomDiffCommands != explicitSBOM || s.contractDiffCommands != explicitContract {
		t.Fatal("rebind replaced injected diff ports")
	}
	missing := ingestionDiffFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}, clock: clock}
	if err := missing.AuthorizeCreateSBOMDiff(t.Context(), owner.actor, si); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("missing repositories recovered from aggregate preflight", err)
	}
	if v, err := missing.CreateContractDiff(t.Context(), owner.actor, ci); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.ContractDiff{}) {
		t.Fatal("missing repositories recovered aggregate write", err)
	}
}

func TestDiffNativeFixtureValidatesRequestedReleaseWithoutInventingScope(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceReadFixtureScope(t, ledger, "Foreign")
	target, err := ledger.UploadSBOM(t.Context(), owner.actor, owner.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := ledger.UploadOpenAPIContract(t.Context(), owner.actor, owner.product.ID, owner.release.ID, "2", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	third, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "3")
	if err != nil {
		t.Fatal(err)
	}
	f := ingestionDiffFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	si := evidenceapp.CreateSBOMDiffInput{BaseSBOMID: owner.sbom.ID, TargetSBOMID: target.ID, ReleaseID: third.ID}
	ci := evidenceapp.CreateContractDiffInput{BaseContractID: owner.contract.ID, TargetContractID: contract.ID, ReleaseID: third.ID}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeCreateSBOMDiff(t.Context(), owner.actor, si); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("SBOM accepted unrelated release", err)
	}
	if v, err := f.CreateSBOMDiff(t.Context(), owner.actor, si); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.SBOMDiff{}) {
		t.Fatal("SBOM generated unrelated release diff", err)
	}
	ci.ReleaseID = foreign.release.ID
	if err := f.AuthorizeCreateContractDiff(t.Context(), owner.actor, ci); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("contract accepted foreign requested release", err)
	}
	if v, err := f.CreateContractDiff(t.Context(), owner.actor, ci); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.ContractDiff{}) {
		t.Fatal("contract generated foreign release diff", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("invalid requested release changed state", err)
	}
	// Unlike SBOM diffs, a contract diff may target a third current release of
	// the shared product; the actual focused guard and command must agree.
	ci.ReleaseID = third.ID
	if err := f.AuthorizeCreateContractDiff(t.Context(), owner.actor, ci); err != nil {
		t.Fatal("third same-product release preflight", err)
	}
	if v, err := f.CreateContractDiff(t.Context(), owner.actor, ci); err != nil || v.ReleaseID != third.ID || v.ProductID != owner.product.ID || v.Result != "breaking" {
		t.Fatal("third same-product release command", v, err)
	}
}
