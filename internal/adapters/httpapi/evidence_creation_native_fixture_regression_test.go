package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestEvidenceCreationFixtureUsesCurrentScopeAndExactCanonicalFieldsWithoutAggregateClock(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("evidence creation used aggregate clock") }})
	f := evidenceFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	in := evidenceapp.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Subtype: "note", Title: "Recorded", PayloadHash: "sha256:" + strings.Repeat("a", 64), SourceSystem: "fixture", SourceIdentity: map[string]any{"run": json.Number("9007199254740993")}, Metadata: map[string]any{"nested": map[string]any{"number": json.Number("9007199254740993")}}, Tags: []string{"b", "a"}, Limitations: []string{"recorded evidence only"}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeEvidenceCreation(t.Context(), owner.actor, in); err != nil {
		t.Fatal("current creation preflight rejected", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("evidence creation guard wrote effects", err)
	}
	started := factory.begins
	v, err := f.CreateEvidence(t.Context(), owner.actor, in)
	if err != nil || v.ID == "" || v.ChainEntryID == "" || v.TenantID != owner.actor.TenantID || v.ProductID != owner.product.ID || v.Canonicalization != evidencedomain.EvidenceCanonicalizationProfileVersion || !reflect.DeepEqual(v.Metadata, in.Metadata) || !reflect.DeepEqual(v.SourceIdentity, in.SourceIdentity) {
		t.Fatal("focused creation lost current scope or exact fields", err)
	}
	steps := factory.begins - started
	after, err := base.Snapshot()
	// Compare every persisted JSON field; omitempty intentionally normalizes
	// empty Warnings/RelatedEvidenceRefs slices without changing the record.
	storedJSON, storedErr := json.Marshal(after.Evidence[v.ID])
	expectedJSON, expectedErr := json.Marshal(domain.EvidenceFromContextModel(v))
	if err != nil || storedErr != nil || expectedErr != nil || len(after.Evidence) != len(before.Evidence)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || len(after.OutboxJobs) != len(before.OutboxJobs) || string(storedJSON) != string(expectedJSON) {
		t.Fatal("evidence/audit did not commit exact canonical fields", err)
	}
	verification, err := (verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}).VerifySubject(t.Context(), owner.actor, "evidence_item", v.ID)
	if err != nil || verification.Result.String() != "passed" {
		t.Fatal("created evidence canonical fields no longer verify", err)
	}
	beforeFailure, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// The final transaction owns the real evidence/audit write. Exercise that
	// commit, not an earlier preparation lookup, using the observed phase count.
	factory.failAt = factory.begins + steps
	if v, err := f.CreateEvidence(t.Context(), owner.actor, in); err == nil || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) || factory.begins != factory.failAt {
		t.Fatal("write commit failure not exercised or exposed evidence", err)
	}
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(beforeFailure, failed) {
		t.Fatal("failed evidence write commit published effects", err)
	}
}

func TestEvidenceCreationFixtureRejectsMissingRepositoryForeignScopeRemovedGrantsAndCancellation(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	f := evidenceFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	in := evidenceapp.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Title: "Recorded", PayloadHash: "sha256:" + strings.Repeat("b", 64)}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := f.CreateEvidence(t.Context(), foreign.actor, in); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("foreign creation scope accepted", err)
	}
	human := owner.actor
	human.KeyID, human.UserID = "", "human"
	if v, err := f.CreateEvidence(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("missing product grant allowed creation", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.CreateEvidence(ctx, owner.actor, in); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("cancelled creation returned evidence", err)
	}
	bare := evidenceFixtureCommands{catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}}
	if v, err := bare.CreateEvidence(t.Context(), owner.actor, in); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("missing repository restored aggregate creation", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied/cancelled creation left effects", err)
	}
}
