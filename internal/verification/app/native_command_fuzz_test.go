package app_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func nativeFuzzRunSnapshotCommand(t *testing.T, ctx context.Context, s *nativeFuzzPorts, actor identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	t.Helper()
	clock := application.ClockFunc(func() time.Time { return nativeFuzzNow })
	switch kind {
	case "audit_chain":
		c, err := verificationapp.NewAuditChainVerificationCommands(verificationapp.AuditChainVerificationConfig{Transactions: s, Authorizer: s, Hasher: integrityFuzzHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyAuditChain(ctx, actor)
	case "evidence_item":
		c, err := verificationapp.NewEvidenceVerificationCommands(verificationapp.EvidenceVerificationConfig{Transactions: s, Authorizer: s, Hasher: nativeFuzzEvidenceHasher{}, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyEvidence(ctx, actor, id)
	case "artifact_signature":
		c, err := verificationapp.NewArtifactSignatureVerificationCommands(verificationapp.ArtifactSignatureVerificationConfig{Transactions: s, Authorizer: s, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyArtifactSignature(ctx, actor, id)
	case "backup_manifest":
		c, err := verificationapp.NewBackupVerificationCommands(verificationapp.BackupVerificationConfig{Transactions: s, Authorizer: s, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyBackupManifest(ctx, actor, id)
	case "merkle_batch":
		c, err := verificationapp.NewMerkleVerificationCommands(verificationapp.MerkleVerificationConfig{Transactions: s, Authorizer: s, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyMerkleBatch(ctx, actor, id)
	case "release_bundle":
		c, err := verificationapp.NewReleaseBundleVerificationCommands(verificationapp.ReleaseBundleVerificationConfig{Transactions: s, Authorizer: s, Hasher: integrityFuzzHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: nativeFuzzIDs()})
		if err != nil {
			t.Fatal(err)
		}
		return c.VerifyReleaseBundle(ctx, actor, id)
	default:
		t.Fatal("unknown native snapshot property")
		return verificationdomain.VerificationResult{}, verificationapp.ErrValidation
	}
}

func nativeFuzzSnapshotCommandProperty(t *testing.T, fixture func() *nativeFuzzPorts, kind, id, expected string, mode uint8) {
	t.Helper()
	actor := nativeFuzzActor()
	s := fixture()
	before := nativeFuzzJSON(t, []any{s.pages, s.evidence, s.artifact, s.backup, s.merkle, s.bundle})
	positive, err := nativeFuzzRunSnapshotCommand(t, t.Context(), s, actor, kind, id)
	if err != nil {
		t.Fatalf("native snapshot command rejected: %v", err)
	}
	nativeFuzzAssertReceipt(t, s, positive, kind, id, expected)
	again, err := nativeFuzzRunSnapshotCommand(t, t.Context(), fixture(), actor, kind, id)
	if err != nil || !reflect.DeepEqual(positive, again) {
		t.Fatal("native snapshot receipt is not stable")
	}
	if nativeFuzzJSON(t, []any{s.pages, s.evidence, s.artifact, s.backup, s.merkle, s.bundle}) != before {
		t.Fatal("native snapshot command mutated source")
	}
	failed := fixture()
	failed.fail = []string{"result", "audit", "outbox", "commit"}[mode%4]
	if _, err := nativeFuzzRunSnapshotCommand(t, t.Context(), failed, actor, kind, id); !errors.Is(err, errNativeFuzzWrite) {
		t.Fatal("native snapshot receipt failure was not propagated")
	}
	nativeFuzzAssertNoWrites(t, failed)
	foreign := fixture()
	switch kind {
	case "audit_chain":
		foreign.view.TenantID = "foreign"
	case "evidence_item", "artifact_signature", "merkle_batch", "release_bundle":
		foreign.subject.TenantID = "foreign"
	case "backup_manifest":
		foreign.backup.Subject.TenantID = "foreign"
	}
	if _, err := nativeFuzzRunSnapshotCommand(t, t.Context(), foreign, actor, kind, id); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign native snapshot accepted")
	}
	if kind != "backup_manifest" && foreign.payloads+foreign.reads != 0 {
		t.Fatal("foreign snapshot identity triggered a payload read")
	}
	nativeFuzzAssertNoWrites(t, foreign)
	denied := fixture()
	actor.Scopes = nil
	if _, err := nativeFuzzRunSnapshotCommand(t, t.Context(), denied, actor, kind, id); !errors.Is(err, application.ErrForbidden) || denied.payloads+denied.reads != 0 {
		t.Fatal("removed capability read native snapshot")
	}
	nativeFuzzAssertNoWrites(t, denied)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	canceled := fixture()
	if _, err := nativeFuzzRunSnapshotCommand(t, ctx, canceled, nativeFuzzActor(), kind, id); !errors.Is(err, context.Canceled) || canceled.payloads+canceled.reads != 0 {
		t.Fatal("canceled native snapshot command read content")
	}
	nativeFuzzAssertNoWrites(t, canceled)
}
