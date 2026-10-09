package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureQueryObjectTrap struct{ *signatureFixtureStore }

func (*signatureQueryObjectTrap) Get(context.Context, string) (app.Object, error) {
	panic("signature metadata query attempted a payload read")
}

func TestArtifactSignatureNativeCommandUsesCurrentRepositoryClockAndAtomicEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("signature creation used aggregate clock") }})
	commands := artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, objects: objects}
	input := verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", KeyID: "public-key", Signature: "recorded", RawPayload: []byte(`{"private":"native-command-payload"}`), PayloadMediaType: "application/json"}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeArtifactSignatureCreation(t.Context(), owner.actor, input); err != nil {
		t.Fatal("native guard lost current ownership", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) || objects.stages != 0 {
		t.Fatal("signature preflight wrote or staged effects", err)
	}
	value, err := commands.CreateArtifactSignature(t.Context(), owner.actor, input)
	if err != nil || value.ID == "" || value.ArtifactID != owner.artifact.ID || value.SubjectDigest != owner.artifact.Digest || value.KeyID != input.KeyID || value.Signature != input.Signature || value.PayloadRef == "" || value.PayloadHash == "" || value.VerificationStatus != "recorded" {
		t.Fatal("native signature creation lost current digest/public fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.ArtifactSignatures) != len(before.ArtifactSignatures)+1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || objects.stages != 1 {
		t.Fatal("signature/payload/audit/job effects did not commit together", err)
	}
	factory.fail = true
	value, err = commands.CreateArtifactSignature(t.Context(), owner.actor, input)
	if err == nil || value != (verificationdomain.ArtifactSignature{}) {
		t.Fatal("failed creation commit exposed signature", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed creation commit published partial repository effects", err)
	}
}

func TestArtifactSignatureNativeCommandRequiresRepositoryAndPreservesExplicitResources(t *testing.T) {
	ledger, factory, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	bare := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", Now: func() time.Time { panic("missing-repository command used aggregate clock") }})
	commands := artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: bare}, objects: objects}
	input := verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", Signature: "recorded", RawPayload: []byte(`{"private":"unstaged"}`), PayloadMediaType: "application/json"}
	value, err := commands.CreateArtifactSignature(t.Context(), owner.actor, input)
	if !errors.Is(err, app.ErrValidation) || value != (verificationdomain.ArtifactSignature{}) || objects.stages != 0 {
		t.Fatal("missing repository restored aggregate creation or staged bytes", err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("native command used aggregate clock") }})
	explicit := &artifactSignatureQueryFake{}
	server := &Server{artifactSignatureCommands: artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects}, artifactSignatureQuery: explicit}
	server.bindArtifactSignatureFixturePorts(rebound)
	bound, ok := server.artifactSignatureCommands.(artifactSignatureFixture)
	if !ok || bound.ledger != rebound || bound.objects != objects || server.artifactSignatureQuery != explicit {
		t.Fatal("rebind lost explicit payload storage or replaced a focused query")
	}
	denied := owner.actor
	denied.Scopes = nil
	if _, err := bound.CreateArtifactSignature(t.Context(), denied, input); !errors.Is(err, app.ErrForbidden) || objects.stages != 0 {
		t.Fatal("unauthorized command reached payload staging", err)
	}
}

func TestArtifactSignatureNativeFixtureUsesCurrentRepositoryAndReturnsNothingOnFailedCommit(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	signature, err := createFixtureArtifactSignature(t.Context(), ledger, objects, owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", KeyID: "public-key", Signature: "recorded-signature", RawPayload: []byte(`{"private_marker":"unselected-payload"}`), PayloadMediaType: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, ObjectStore: &signatureQueryObjectTrap{objects}, Now: func() time.Time { panic("signature metadata query used aggregate clock") }})
	query := artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	value, err := query.GetArtifactSignature(t.Context(), owner.actor, signature.ID)
	if err != nil || value != verificationdomain.ArtifactSignature(signature) {
		t.Fatal("native signature read lost current public metadata or used aggregate caches", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("signature read changed repository state", err)
	}
	factory.fail = true
	value, err = query.GetArtifactSignature(t.Context(), owner.actor, signature.ID)
	if err == nil || value != (verificationdomain.ArtifactSignature{}) {
		t.Fatal("failed read commit exposed signature metadata", err)
	}
}

func TestArtifactSignatureNativeFixtureRequiresRepositoryAndPreservesExplicitPort(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", Now: func() time.Time { panic("signature query used aggregate clock") }})
	query := artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}
	value, err := query.GetArtifactSignature(t.Context(), actor, "signature")
	if !errors.Is(err, app.ErrValidation) || value != (verificationdomain.ArtifactSignature{}) {
		t.Fatal("missing repository restored a cached lookup or exposed data", err)
	}
	actor.Scopes = nil
	if _, err := query.GetArtifactSignature(t.Context(), actor, "signature"); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("missing authority reached repository lookup", err)
	}
	actor.Scopes = []string{"evidence:read"}
	var missingContext context.Context
	if _, err := query.GetArtifactSignature(missingContext, actor, "signature"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.GetArtifactSignature(ctx, actor, "signature"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated", err)
	}
	explicit := &artifactSignatureQueryFake{}
	server := &Server{artifactSignatureQuery: explicit}
	server.bindArtifactSignatureFixturePorts(ledger)
	if server.artifactSignatureQuery != explicit {
		t.Fatal("fixture rebinding replaced an explicit focused query")
	}
}
