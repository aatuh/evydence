package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestMetadataVerificationNativeFixturesHTTPReplayAndCanonicalFailureRollback(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	sig, err := (artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateArtifactSignature(t.Context(), owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "recorded", Signature: "opaque"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	bad := owner.original
	bad.ID, bad.CanonicalHash, bad.ChainEntryID = "corrupt-evidence", "sha256:"+strings.Repeat("f", 64), ""
	if err := tx.Repositories().Evidence.InsertEvidence(t.Context(), bad); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: fixtureIdentityAuthenticator(ledger, "fixture-pepper", providerVerificationFixtureClock())})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, id, result string }{{"evidence_item", owner.original.ID, "passed"}, {"artifact_signature", sig.ID, "limited"}} {
		body := fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, tc.kind, tc.id)
		one := postRaw(t, server, owner.secret, "/v1/verify", tc.kind, []byte(body), 200)
		if !strings.Contains(one, fmt.Sprintf(`"result":%q`, tc.result)) || !strings.Contains(one, `"transparency_proof":"not_evaluated"`) {
			t.Fatal("HTTP metadata verification changed assurance profile", tc.kind)
		}
		beforeReplay, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, one, postRaw(t, server, owner.secret, "/v1/verify", tc.kind, []byte(body), 200))
		afterReplay, err := factory.Snapshot()
		if err != nil || !reflect.DeepEqual(beforeReplay, afterReplay) {
			t.Fatal("metadata verification replay repeated business effects", err)
		}
	}
	beforeFailedPOST, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"subject_type":"evidence_item","subject_id":%q}`, bad.ID)
	postRaw(t, server, owner.secret, "/v1/verify", "canonical-failure", []byte(body), 422)
	afterFailedPOST, err := factory.Snapshot()
	if err != nil || len(afterFailedPOST.Idempotency) != len(beforeFailedPOST.Idempotency)+1 {
		t.Fatal("canonical failure lost its failed reservation", err)
	}
	for key, receipt := range afterFailedPOST.Idempotency {
		if _, existed := beforeFailedPOST.Idempotency[key]; !existed && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
			t.Fatal("failed canonical verification retained partial success")
		}
	}
	afterFailedPOST.Idempotency = beforeFailedPOST.Idempotency
	if !reflect.DeepEqual(beforeFailedPOST, afterFailedPOST) {
		t.Fatal("failed canonical verification committed partial receipt/audit/job")
	}
}

func TestMetadataVerificationNativeFixturesEnforceCurrentGrantsAndAtomicCommitFailure(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	sig, err := (artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateArtifactSignature(t.Context(), owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "recorded", Signature: "opaque"})
	if err != nil {
		t.Fatal(err)
	}
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	human := owner.actor
	human.KeyID, human.UserID = "", "human"
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"verify:read"}}}
	if err := f.AuthorizeSubjectVerification(t.Context(), human, "evidence_item", owner.original.ID); err != nil {
		t.Fatal("current product grant did not authorize canonical evidence", err)
	}
	if err := f.AuthorizeSubjectVerification(t.Context(), human, "artifact_signature", sig.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("product grant became detached-signature verification authority", err)
	}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"verify:read"}}}
	for _, tc := range []struct{ kind, id string }{{"evidence_item", owner.original.ID}, {"artifact_signature", sig.ID}} {
		if err := f.AuthorizeSubjectVerification(t.Context(), human, tc.kind, tc.id); err != nil {
			t.Fatal("current tenant grant rejected", err)
		}
		if v, err := f.VerifySubject(t.Context(), foreign.actor, tc.kind, tc.id); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
			t.Fatal("foreign verification exposed facts", tc.kind, err)
		}
		denied := human
		denied.ResourceGrants = nil
		if err := f.AuthorizeSubjectVerification(t.Context(), denied, tc.kind, tc.id); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("removed grant retained verification replay authority", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if v, err := f.VerifySubject(ctx, owner.actor, tc.kind, tc.id); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
			t.Fatal("cancelled verification returned partial receipt", err)
		}
		factory.failAt = factory.begins + 1
		if v, err := f.VerifySubject(t.Context(), owner.actor, tc.kind, tc.id); err == nil || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) || factory.begins != factory.failAt {
			t.Fatal("verification commit failure not exercised or returned receipt", err)
		}
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("verification guards, denied/cancelled calls or commit failures left effects", err)
	}
}

func TestMetadataVerificationNativeFixturesUseCurrentFactsWithoutAggregateCache(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	sig, err := (artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateArtifactSignature(t.Context(), owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "recorded", Signature: "opaque-recorded-not-verified"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("metadata verification used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	for _, tc := range []struct{ kind, id, result, profile string }{
		{"evidence_item", owner.original.ID, "passed", "evidence-canonical-hash.v1"},
		{"artifact_signature", sig.ID, "limited", "artifact-signature-metadata.v1"},
	} {
		v, err := f.VerifySubject(t.Context(), owner.actor, tc.kind, tc.id)
		if err != nil || v.ID == "" || v.Result.String() != tc.result || v.Profile.ID != tc.profile || v.Profile.TransparencyProof != "not_evaluated" || len(v.Profile.Limitations) == 0 {
			t.Fatal("metadata verification lost current facts or assurance boundary", tc.kind, err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+2 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || !reflect.DeepEqual(after.Evidence, before.Evidence) || !reflect.DeepEqual(after.ArtifactSignatures, before.ArtifactSignatures) {
		t.Fatal("metadata verification escaped atomic receipt/audit/job paths", err)
	}
}

func TestEvidenceCreationFixtureGuardUsesCurrentParentsWithoutAggregate(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("evidence guard allocated aggregate time") }})
	f := evidenceFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	in := evidenceapp.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Title: "Guard", PayloadHash: owner.original.PayloadHash}
	if err := f.AuthorizeEvidenceCreation(t.Context(), owner.actor, in); err != nil {
		t.Fatal("creation guard missed current parents", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("creation guard wrote effects", err)
	}
}
