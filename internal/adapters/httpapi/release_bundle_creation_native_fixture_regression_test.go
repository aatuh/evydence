package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type bundleWriteFailureFactory struct {
	base           *app.MemoryUnitOfWorkFactory
	begins, failAt int
}
type bundleWriteFailureTransaction struct {
	app.UnitOfWork
	fail bool
}

func (f *bundleWriteFailureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	f.begins++
	u, err := f.base.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return bundleWriteFailureTransaction{u, f.begins == f.failAt}, nil
}
func (u bundleWriteFailureTransaction) Commit(ctx context.Context) error {
	if u.fail {
		return errors.New("private-bundle-write-commit-failure")
	}
	return u.UnitOfWork.Commit(ctx)
}

func TestReleaseBundleCreationNativeFixtureUsesCurrentSnapshotKeyAndAtomicWrites(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("bundle creation used aggregate clock") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeReleaseBundleCreation(t.Context(), owner.actor, owner.release.ID); err != nil {
		t.Fatal("release guard consulted empty aggregate cache", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("release bundle guard wrote effects", err)
	}
	bundle, err := f.CreateReleaseBundle(t.Context(), owner.actor, owner.release.ID)
	if err != nil || bundle.ReleaseID != owner.release.ID || bundle.ManifestHash == "" || len(bundle.SignatureRefs) != 1 || bundle.State.String() != "generated" {
		t.Fatal("focused bundle creation failed", bundle, err)
	}
	bundle.Manifest["caller_mutation"] = "changed"
	after, err := base.Snapshot()
	if err != nil || len(after.ReleaseBundles) != len(before.ReleaseBundles)+1 || len(after.Signatures) != len(before.Signatures)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("bundle/signature/audit/outbox writes were not atomic", err)
	}
	sig := after.Signatures[bundle.SignatureRefs[0]]
	if sig.SubjectType != "release_bundle" || sig.SubjectID != bundle.ID || sig.TenantID != owner.actor.TenantID || after.ReleaseBundles[bundle.ID].Manifest["caller_mutation"] != nil {
		t.Fatal("signature binding or frozen manifest changed")
	}
	factory.fail = true
	if value, err := f.CreateReleaseBundle(t.Context(), owner.actor, owner.release.ID); err == nil || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) {
		t.Fatal("failed bundle commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed bundle commit published partial writes", err)
	}
	factory.fail = false
	writeFailure := &bundleWriteFailureFactory{base: base}
	writer := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: writeFailure})
	writeFailure.failAt = writeFailure.begins + 3 // Snapshot, signing, then write commit.
	if value, err := (releaseBundleFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: writer}}).CreateReleaseBundle(t.Context(), owner.actor, owner.release.ID); err == nil || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) || writeFailure.begins != writeFailure.failAt {
		t.Fatal("write-phase failure did not roll back after real signing", err)
	}
	last, err = base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed bundle write phase published signature, bundle, audit or job", err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeBundleWrite}}
	if err := f.AuthorizeReleaseBundleCreation(t.Context(), human, owner.release.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked grant authorized release bundle", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := f.CreateReleaseBundle(ctx, owner.actor, owner.release.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) {
		t.Fatal("cancelled bundle returned data", err)
	}
}

func TestReleaseBundleVerificationNativeFixtureUsesCurrentRowsAndAtomicReceipt(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	bundle, err := createReleaseBundleFixture(t.Context(), ledger, owner.actor, owner.release.ID, owner.release.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("bundle verifier consulted aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeSubjectVerification(t.Context(), owner.actor, "release_bundle", bundle.ID); err != nil {
		t.Fatal("verification guard consulted empty bundle cache", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("verification guard wrote effects", err)
	}
	v, err := f.VerifyReleaseBundle(t.Context(), owner.actor, bundle.ID)
	if err != nil || v.Result.String() != "passed" || v.SubjectID != bundle.ID || len(v.Checks) != 2 || v.Profile.PayloadDigest != bundle.ManifestHash {
		t.Fatal("real current bundle verification failed", v, err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || !reflect.DeepEqual(before.ReleaseBundles, after.ReleaseBundles) || !reflect.DeepEqual(before.SigningKeys, after.SigningKeys) {
		t.Fatal("verification receipt effects changed immutable material", err)
	}
	factory.failAt = factory.begins + 1
	if value, err := f.VerifyReleaseBundle(t.Context(), owner.actor, bundle.ID); err == nil || !reflect.DeepEqual(value, verificationdomain.VerificationResult{}) {
		t.Fatal("failed verification commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) {
		t.Fatal("failed verification committed receipt/audit/job", err)
	}
	factory.failAt = 0
	if value, err := f.VerifyReleaseBundle(t.Context(), foreign.actor, bundle.ID); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(value, verificationdomain.VerificationResult{}) {
		t.Fatal("foreign bundle verification returned data", err)
	}
	denied := owner.actor
	denied.KeyID = ""
	denied.UserID = "human"
	denied.Scopes = []string{app.ScopeVerifyRead}
	denied.ResourceGrants = nil
	if value, err := f.VerifyReleaseBundle(t.Context(), denied, bundle.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(value, verificationdomain.VerificationResult{}) {
		t.Fatal("missing current verification grant accepted", err)
	}
}
