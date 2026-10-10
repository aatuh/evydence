package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestEvidenceBundleExportNativeFixtureUsesCurrentSelectionKeyAndAtomicWrites(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	writeFailure := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: writeFailure, Now: func() time.Time { panic("export used aggregate clock") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{owner.evidence.ID}
	guard := evidenceBundleFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands, clock: application.ClockFunc(func() time.Time { panic("export guard allocated time") })}
	if err := guard.AuthorizeEvidenceBundleExport(t.Context(), owner.actor, owner.release.ID, ids); err != nil {
		t.Fatal("export guard read missing aggregate cache", err)
	}
	if err := guard.AuthorizeEvidenceBundleReplay(t.Context(), owner.actor, owner.release.ID, ids); err != nil {
		t.Fatal("replay guard read missing aggregate cache", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("export/replay guards wrote effects", err)
	}
	bundle, err := f.ExportEvidenceBundle(t.Context(), owner.actor, owner.release.ID, ids)
	if err != nil || !reflect.DeepEqual(bundle.EvidenceIDs, ids) || bundle.ReleaseID != owner.release.ID || bundle.ManifestHash == "" || len(bundle.SignatureRefs) != 1 || bundle.SchemaVersion != "evidence-bundle.v1.0.0" || bundle.VerificationText == "" {
		t.Fatal("focused export lost its public contract", bundle, err)
	}
	bundle.Manifest["caller_mutation"] = "changed"
	after, err := base.Snapshot()
	if err != nil || len(after.EvidenceBundles) != len(before.EvidenceBundles)+1 || len(after.Signatures) != len(before.Signatures)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || len(after.OutboxJobs) != len(before.OutboxJobs) || !reflect.DeepEqual(after.Evidence, before.Evidence) {
		t.Fatal("export signature/bundle/audit effects escaped atomic scope", err)
	}
	sig := after.Signatures[bundle.SignatureRefs[0]]
	if sig.SubjectType != "evidence_bundle" || sig.SubjectID != bundle.ID || after.EvidenceBundles[bundle.ID].Manifest["caller_mutation"] != nil {
		t.Fatal("export signature binding or detachment failed")
	}
	writeFailure.failAt = writeFailure.begins + 3
	if value, err := f.ExportEvidenceBundle(t.Context(), owner.actor, owner.release.ID, ids); err == nil || !reflect.DeepEqual(value, packagedomain.EvidenceBundle{}) || writeFailure.begins != writeFailure.failAt {
		t.Fatal("export write failure did not occur after real signing", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed export write committed partial effects", err)
	}
}

func TestEvidenceBundleExportNativeFixtureFiltersCurrentGrantsAndRejectsForeignReferences(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	other, err := ledger.CreateProduct(t.Context(), owner.actor, "Other product", "other-product")
	if err != nil {
		t.Fatal(err)
	}
	item, err := ledger.CreateEvidence(t.Context(), owner.actor, app.CreateEvidenceInput{ProductID: other.ID, Type: "document", Title: "Private source label", PayloadHash: "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	f := packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeBundleRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeBundleRead}}}}
	bundle, err := f.ExportEvidenceBundle(t.Context(), human, "", nil)
	if err != nil || len(bundle.EvidenceIDs) != 1 || bundle.EvidenceIDs[0] != owner.evidence.ID {
		t.Fatal("automatic export failed current grant filtering", bundle.EvidenceIDs, err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ExportEvidenceBundle(t.Context(), human, "", []string{item.ID}); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("explicit ungranted evidence exported", err)
	}
	if value, err := f.ExportEvidenceBundle(t.Context(), owner.actor, "", []string{foreign.evidence.ID}); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(value, packagedomain.EvidenceBundle{}) {
		t.Fatal("foreign explicit evidence exported", err)
	}
	if value, err := f.ExportEvidenceBundle(t.Context(), owner.actor, foreign.release.ID, nil); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(value, packagedomain.EvidenceBundle{}) {
		t.Fatal("foreign release exported", err)
	}
	if err := f.AuthorizeEvidenceBundleReplay(t.Context(), owner.actor, "", []string{foreign.evidence.ID}); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign saved selection replay authorized", err)
	}
	human.ResourceGrants = nil
	if err := f.AuthorizeEvidenceBundleReplay(t.Context(), human, "", bundle.EvidenceIDs); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked grant replayed original selection", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := f.ExportEvidenceBundle(ctx, owner.actor, "", nil); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagedomain.EvidenceBundle{}) {
		t.Fatal("cancelled export returned data", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied export/replay wrote effects", err)
	}
}

func TestEvidenceBundleExportNativeFixtureRejectsMissingRepositories(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := evidenceBundleFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{app.ScopeBundleRead}}
	if err := f.AuthorizeEvidenceBundleExport(t.Context(), actor, "", nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("export guard used aggregate fallback", err)
	}
	if err := f.AuthorizeEvidenceBundleReplay(t.Context(), actor, "", []string{"saved"}); !errors.Is(err, app.ErrValidation) {
		t.Fatal("replay guard used aggregate fallback", err)
	}
	if value, err := f.ExportEvidenceBundle(t.Context(), actor, "", nil); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, packagedomain.EvidenceBundle{}) {
		t.Fatal("export used aggregate fallback", err)
	}
}
