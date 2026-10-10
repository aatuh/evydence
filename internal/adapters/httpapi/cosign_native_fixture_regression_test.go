package httpapi

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestCosignNativeFixtureUsesCurrentSignatureAndCommitsOnlyUnavailableReceipts(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	signature, err := createFixtureArtifactSignature(t.Context(), ledger, objects, owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", Signature: "recorded"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("Cosign fixture used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	input := verificationapp.VerifyCosignInput{ArtifactSignatureID: signature.ID, Mode: verificationapp.CosignVerificationModeKeyless, Offline: true, ExpectedIdentity: "repo:example/project", ExpectedIssuer: "https://issuer.example"}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.VerifyCosign(t.Context(), owner.actor, input)
	if !errors.Is(err, app.ErrFullVerificationUnavailable) || v.ID == "" || v.Result != verificationdomain.VerificationStateLimited || v.ArtifactSignatureID != signature.ID || v.SubjectDigest != owner.artifact.Digest {
		t.Fatal("unconfigured verification lost current binding or became success", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.CosignVerifications) != len(before.CosignVerifications)+1 || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("unavailable receipts and audit did not commit together", err)
	}
	factory.fail = true
	v, err = f.VerifyCosign(t.Context(), owner.actor, input)
	if err == nil || !reflect.DeepEqual(v, verificationdomain.CosignVerification{}) {
		t.Fatal("failed commit exposed verification receipt", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed verification commit published effects", err)
	}
}
