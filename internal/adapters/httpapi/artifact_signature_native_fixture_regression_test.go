package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureQueryObjectTrap struct{ *signatureFixtureStore }

func (*signatureQueryObjectTrap) Get(context.Context, string) (app.Object, error) {
	panic("signature metadata query attempted a payload read")
}

func TestArtifactSignatureNativeFixtureUsesCurrentRepositoryAndReturnsNothingOnFailedCommit(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	signature, err := ledger.CreateArtifactSignature(t.Context(), owner.actor, app.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", KeyID: "public-key", Signature: "recorded-signature", RawPayload: []byte(`{"private_marker":"unselected-payload"}`), PayloadMediaType: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, ObjectStore: &signatureQueryObjectTrap{objects}, Now: func() time.Time { panic("signature metadata query used aggregate clock") }})
	query := artifactSignatureFixture{catalogFixtureCommands{ledger: rebound}}
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
	query := artifactSignatureFixture{catalogFixtureCommands{ledger: ledger}}
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
