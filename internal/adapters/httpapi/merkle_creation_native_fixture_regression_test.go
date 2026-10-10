package httpapi

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestMerkleVerificationNativeFixtureRecordsNegativeFactsWithoutTrustOrForeignEffects(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	tx, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if err := tx.Repositories().Integrity.InsertMerkleBatch(t.Context(), domain.MerkleBatch{ID: "negative-batch", TenantID: owner.actor.TenantID, FromSequence: 1, ToSequence: 1, EntryCount: 1, RootHash: "recorded", LeafHashes: []string{"wrong-recorded-hash"}, SignatureRefs: []string{}, SchemaVersion: "merkle_batch.v1", CreatedAt: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f := verificationReadFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	foreign := owner.actor
	foreign.TenantID = "foreign"
	if v, err := f.VerifyMerkleBatch(t.Context(), foreign, "negative-batch"); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
		t.Fatal("foreign verification returned data or unexpected error", err)
	}
	afterForeign, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, afterForeign) {
		t.Fatal("foreign verification left effects", err)
	}
	v, err := f.VerifyMerkleBatch(t.Context(), owner.actor, "negative-batch")
	if !errors.Is(err, app.ErrVerificationFailed) || v.ID == "" || v.Result.String() != "failed" || len(v.Checks) != 3 || v.Checks[0].Name != "checkpoint_coverage" || v.Checks[0].Result != "failed" || v.Profile.TransparencyProof != "not_evaluated" {
		t.Fatal("negative facts lost failed receipt contract or overclaimed trust", err)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(after.MerkleBatches, before.MerkleBatches) || !reflect.DeepEqual(after.SigningKeys, before.SigningKeys) {
		t.Fatal("negative verification did not atomically record receipt/audit/job only", err)
	}
}

func TestMerkleCreationNativeFixtureUsesCurrentChainAndKeysWithoutAggregate(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("Merkle command used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	batch, err := f.CreateMerkleBatch(t.Context(), owner.actor, verificationapp.CreateMerkleBatchInput{})
	if err != nil || batch.ID == "" || batch.TenantID != owner.actor.TenantID || batch.FromSequence != 1 || batch.ToSequence != int64(len(before.AuditEntries[owner.actor.TenantID])) || len(batch.SignatureRefs) != 1 {
		t.Fatal("focused batch lost current view or signature", err)
	}
	checkpoint, err := f.CreateTransparencyCheckpoint(t.Context(), owner.actor, verificationapp.CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "recorded", ExternalID: "operator-metadata"})
	if err != nil || checkpoint.ID == "" || checkpoint.BatchID != batch.ID || checkpoint.State != "recorded" || checkpoint.TimestampHash == "" {
		t.Fatal("focused checkpoint lost recorded contract", err)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.MerkleBatches) != len(before.MerkleBatches)+1 || len(after.TransparencyCheckpoints) != len(before.TransparencyCheckpoints)+1 || len(after.Signatures) != len(before.Signatures)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || !reflect.DeepEqual(after.SigningKeys, before.SigningKeys) {
		t.Fatal("batch/checkpoint effects escaped atomic owned paths", err)
	}
	result, err := (verificationReadFixtureCommands{f.catalogFixtureCommands}).VerifyMerkleBatch(t.Context(), owner.actor, batch.ID)
	if err != nil || result.Result.String() != "passed" || len(result.Checks) != 3 {
		t.Fatal("focused Merkle verification lost creation result", err)
	}
}

func TestMerkleCreationNativeFixtureGuardsArePureAndCommitFailuresReturnNoEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory})
	f := merkleCreationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	batch, err := f.CreateMerkleBatch(t.Context(), owner.actor, verificationapp.CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	guard := f
	guard.clock = application.ClockFunc(func() time.Time { panic("Merkle/checkpoint guard allocated time") })
	if err := guard.AuthorizeMerkleCreation(t.Context(), owner.actor); err != nil {
		t.Fatal(err)
	}
	if err := guard.AuthorizeTransparencyCheckpoint(t.Context(), owner.actor, batch.ID); err != nil {
		t.Fatal(err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("Merkle/checkpoint guard changed state", err)
	}
	for _, run := range []func() error{
		func() error {
			v, err := f.CreateMerkleBatch(t.Context(), owner.actor, verificationapp.CreateMerkleBatchInput{})
			if !reflect.DeepEqual(v, verificationdomain.MerkleBatch{}) {
				t.Fatal("failed batch commit returned data")
			}
			return err
		},
		func() error {
			v, err := f.CreateTransparencyCheckpoint(t.Context(), owner.actor, verificationapp.CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "recorded", ExternalID: "operator"})
			if !reflect.DeepEqual(v, verificationdomain.TransparencyCheckpoint{}) {
				t.Fatal("failed checkpoint commit returned data")
			}
			return err
		},
		func() error {
			v, err := (verificationReadFixtureCommands{f.catalogFixtureCommands}).VerifyMerkleBatch(t.Context(), owner.actor, batch.ID)
			if !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
				t.Fatal("failed Merkle verification commit returned data")
			}
			return err
		},
	} {
		factory.failAt = factory.begins + 1
		if err := run(); err == nil || factory.begins != factory.failAt {
			t.Fatal("commit failure not exercised", err)
		}
		after, err := base.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("failed Merkle/checkpoint commit left effects", err)
		}
	}
}
