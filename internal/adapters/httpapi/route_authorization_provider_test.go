package httpapi

import (
	"context"
	"os"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/verification/cosignobjects"
	"github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type authorizationCosignObjectReader struct {
	*signatureFixtureStore
	reads int
}

func (r *authorizationCosignObjectReader) GetBounded(ctx context.Context, key string, limit int64) (app.Object, error) {
	r.reads++
	return r.signatureFixtureStore.GetBounded(ctx, key, limit)
}

func newNativeCosignAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, objects := signatureRegressionLedger(t)
	owner, foreign := seedOperationsFixtureScope(t, ledger, "Owner"), seedOperationsFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner, foreign)
	raw, err := os.ReadFile("../verification/sigstore/testdata/official-othername.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../verification/sigstore/testdata/official-scaffolding.trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sigstore.New(sigstore.Config{TrustedRootJSON: root, TrustRootVersion: "authorization-fixture-root.v1"})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
	f.artifact, err = releaseSetup(ledger).RegisterArtifact(t.Context(), owner.actor, "Signed artifact", "application/octet-stream", digest, 42)
	if err != nil {
		t.Fatal(err)
	}
	f.signature, err = createFixtureArtifactSignature(t.Context(), ledger, objects, owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: f.artifact.ID, Algorithm: "cosign", Signature: "recorded-only", RawPayload: raw, PayloadMediaType: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, repos app.Repositories) error {
		lifecycle, ok := repos.Payloads.(interface {
			GetObjectPayload(context.Context, string, string) (app.ObjectPayload, error)
			MarkObjectPayloadFinalized(context.Context, app.ObjectPayload) error
		})
		if !ok {
			return app.ErrValidation
		}
		payload, err := lifecycle.GetObjectPayload(ctx, owner.actor.TenantID, f.signature.PayloadHash)
		if err != nil {
			return err
		}
		object, err := objects.FinalizePayload(ctx, payload)
		if err != nil {
			return err
		}
		if err := app.VerifyObjectPayloadRead(payload, object, payload.FinalKey); err != nil {
			return err
		}
		return lifecycle.MarkObjectPayloadFinalized(ctx, payload)
	}); err != nil {
		t.Fatal(err)
	}
	reader := &authorizationCosignObjectReader{signatureFixtureStore: objects}
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	commands, err := verificationapp.NewCosignVerificationCommands(verificationapp.CosignVerificationConfig{Transactions: cosignFixtureTransactions{catalogFixtureCommands{ledger: ledger}}, Authorizer: verificationquery.NewCosignVerificationAuthorizer(), Inspector: cosignobjects.Inspector{Objects: reader, Verifier: verifier}, Clock: clock, IDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	f.server.cosignVerification = commands
	f.externalCalls = func() int { return reader.reads }
	return f
}

func newNativeProviderReceiptAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, live := providerVerificationRegressionLedger()
	owner, foreign := seedProviderVerificationFixture(t, ledger, "Owner"), seedProviderVerificationFixture(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product}, operationsFixtureScope{actor: foreign.actor, product: foreign.product})
	f.sso = owner
	// The live-provider response is a controlled external-I/O seam. The
	// identity commands, policy, receipt redaction and transactions stay native;
	// this does not verify an actual provider account or external credential.
	f.server.bindProviderVerificationFixtureResources(live, providerVerificationFixtureClock())
	f.externalCalls = func() int { return len(live.requests) }
	return f
}

func addNativeProviderAuthorizationCases(cases map[string]func(*testing.T)) {
	cases["verifyCosignSignature"] = nativeMutationAuthorizationFixtureCase("verifyCosignSignature", newNativeCosignAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/artifact-signatures/" + f.signature.ID + "/verify-cosign", []byte(`{"mode":"keyless","offline":true,"expected_identity":"foo!oidc.local","expected_issuer":"http://oidc.local:8080"}`)
	}, nativeMutationExpectation{status: 200, foreignStatus: 404, auditDelta: 1, externalCalls: 1, result: "passed"})
	cases["verifyProviderIdentity"] = nativeMutationAuthorizationFixtureCase("verifyProviderIdentity", newNativeProviderReceiptAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/provider-verifications", []byte(providerVerificationFixtureBody(f.sso, `,"access_token":"authorization-provider-credential-canary"`))
	}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: 1, externalCalls: 1, result: "passed", privateValues: []string{"authorization-provider-credential-canary"}})
}
