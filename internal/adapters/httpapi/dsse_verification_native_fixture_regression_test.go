package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type dsseNativeFixture struct {
	ledger      *repositoryFixture
	base        *app.MemoryUnitOfWorkFactory
	objects     *signatureFixtureStore
	owner       signatureFixtureScope
	build       domain.BuildRun
	attestation domain.BuildAttestation
	raw         []byte
}

func newDSSENativeFixture(t *testing.T, trust bool) dsseNativeFixture {
	t.Helper()
	ledger, base, objects := signatureRegressionLedger(t)
	f := dsseNativeFixture{ledger: ledger, base: base, objects: objects, owner: seedSignatureFixtureScope(t, ledger, "Owner")}
	a := f.owner.actor
	project, err := releaseSetup(ledger).CreateProject(t.Context(), a, f.owner.product.ID, "API")
	if err != nil {
		t.Fatal(err)
	}
	release, err := releaseSetup(ledger).CreateRelease(t.Context(), a, f.owner.product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := releaseSetup(ledger).RegisterArtifact(t.Context(), a, "payments-api.tar.gz", "application/octet-stream", "sha256:"+strings.Repeat("a", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createEvidenceFixture(t.Context(), ledger, a, app.CreateEvidenceInput{ProductID: f.owner.product.ID, ReleaseID: release.ID, Type: "manual", Title: "Release artifact", PayloadHash: artifact.Digest, SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: artifact.ID, Digest: artifact.Digest}}}); err != nil {
		t.Fatal(err)
	}
	f.build, err = releaseSetup(ledger).CreateBuildRun(t.Context(), a, releaseapp.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC), Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if trust {
		_, err := (signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateDSSETrustRoot(t.Context(), a, verificationapp.CreateDSSETrustRootInput{Name: "Builder", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://github.com/actions/runner"}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	payload, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	f.raw, err = json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, securedsse.PAE("application/vnd.in-toto+json", payload)))}}})
	if err != nil {
		t.Fatal(err)
	}
	setup := releaseSetup(ledger)
	setup.objects = objects
	f.attestation, err = setup.UploadBuildAttestation(t.Context(), a, f.build.ID, f.raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		lifecycle, ok := r.Payloads.(interface {
			GetObjectPayload(context.Context, string, string) (app.ObjectPayload, error)
			MarkObjectPayloadFinalized(context.Context, app.ObjectPayload) error
		})
		if !ok {
			return app.ErrValidation
		}
		p, err := lifecycle.GetObjectPayload(ctx, a.TenantID, f.attestation.PayloadHash)
		if err != nil {
			return err
		}
		object, err := objects.FinalizePayload(ctx, p)
		if err != nil {
			return err
		}
		if err := app.VerifyObjectPayloadRead(p, object, p.FinalKey); err != nil {
			return err
		}
		return lifecycle.MarkObjectPayloadFinalized(ctx, p)
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDSSENativeFixtureUsesCurrentPolicyAndCommitsAtomicEffectsWithoutAggregateClock(t *testing.T) {
	seed := newDSSENativeFixture(t, true)
	failure := &bundleWriteFailureFactory{base: seed.base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: failure, Now: func() time.Time { panic("DSSE used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, dsseObjects: seed.objects}
	before, err := seed.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	human := seed.owner.actor
	human.KeyID, human.UserID = "", "human"
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: seed.build.ReleaseID, Scopes: []string{"verify:read"}}}
	if err := f.AuthorizeDSSEVerification(t.Context(), human, seed.attestation.ID); err != nil {
		t.Fatal("current release grant rejected", err)
	}
	denied := human
	denied.ResourceGrants = nil
	if err := f.AuthorizeDSSEVerification(t.Context(), denied, seed.attestation.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("removed grant retained replay access", err)
	}
	foreign := human
	foreign.TenantID = "foreign"
	if _, err := f.VerifyDSSEAttestationSignature(t.Context(), foreign, seed.attestation.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign DSSE read accepted", err)
	}
	guarded, err := seed.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("DSSE guards/denials wrote effects", err)
	}
	v, err := f.VerifySubject(t.Context(), human, "build_attestation", seed.attestation.ID)
	if err != nil || v.ID == "" || v.Result.String() != "passed" || len(v.Checks) != 7 || v.Profile.PayloadDigest != seed.attestation.PayloadHash || v.Profile.TransparencyProof != "not_evaluated" {
		t.Fatal("focused signed DSSE verification failed or changed profile", v, err)
	}
	after, err := seed.base.Snapshot()
	if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
		t.Fatal("DSSE receipt/audit/job not atomic", err)
	}
	failure.failAt = failure.begins + 1
	if v, err := f.VerifyDSSEAttestationSignature(t.Context(), human, seed.attestation.ID); err == nil || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) || failure.begins != failure.failAt {
		t.Fatal("failed DSSE commit exposed receipt or was not exercised", err)
	}
	failed, err := seed.base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed DSSE commit published partial effects", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.VerifyDSSEAttestationSignature(ctx, human, seed.attestation.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
		t.Fatal("cancelled DSSE returned receipt", err)
	}
}

func TestDSSENativeFixtureHTTPReplayAndNegativeVerificationRollback(t *testing.T) {
	seed := newDSSENativeFixture(t, true)
	s, err := newLegacyServerFixtureWithOptions(seed.ledger, ServerOptions{Authenticator: fixtureIdentityAuthenticator(seed.ledger, "fixture-pepper", providerVerificationFixtureClock())})
	if err != nil {
		t.Fatal(err)
	}
	s.bindDSSEVerificationFixtureResources(seed.objects)
	for _, tc := range []struct{ path, key, body string }{
		{"/v1/build-attestations/" + seed.attestation.ID + "/verify-signature", "dedicated-dsse", `{}`},
		{"/v1/verify", "generic-dsse", fmt.Sprintf(`{"subject_type":"build_attestation","subject_id":%q}`, seed.attestation.ID)},
	} {
		one := postRaw(t, s, seed.owner.secret, tc.path, tc.key, []byte(tc.body), 200)
		if !strings.Contains(one, `"result":"passed"`) || strings.Contains(one, `"payload_ref"`) || strings.Contains(one, `"signatures"`) {
			t.Fatal("DSSE response assurance/privacy changed")
		}
		before, err := seed.base.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, one, postRaw(t, s, seed.owner.secret, tc.path, tc.key, []byte(tc.body), 200))
		after, err := seed.base.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("DSSE replay repeated receipt/audit/job effects", err)
		}
	}
	// Structurally valid envelope metadata cannot substitute for a valid PAE
	// signature, even when its claimed subject matches registered outputs.
	var envelope map[string]any
	if err := json.Unmarshal(seed.raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["signatures"] = []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	badRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	setup := releaseSetup(seed.ledger)
	setup.objects = seed.objects
	bad, err := setup.UploadBuildAttestation(t.Context(), seed.owner.actor, seed.build.ID, badRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		p, err := r.Payloads.(interface {
			GetObjectPayload(context.Context, string, string) (app.ObjectPayload, error)
		}).GetObjectPayload(ctx, seed.owner.actor.TenantID, bad.PayloadHash)
		if err != nil {
			return err
		}
		o, err := seed.objects.FinalizePayload(ctx, p)
		if err != nil {
			return err
		}
		if err := app.VerifyObjectPayloadRead(p, o, p.FinalKey); err != nil {
			return err
		}
		return r.Payloads.(interface {
			MarkObjectPayloadFinalized(context.Context, app.ObjectPayload) error
		}).MarkObjectPayloadFinalized(ctx, p)
	}); err != nil {
		t.Fatal(err)
	}
	before, err := seed.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	postRaw(t, s, seed.owner.secret, "/v1/build-attestations/"+bad.ID+"/verify-signature", "invalid-signature", []byte(`{}`), 422)
	after, err := seed.base.Snapshot()
	if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("negative DSSE lost failed reservation", err)
	}
	for key, record := range after.Idempotency {
		if _, existed := before.Idempotency[key]; !existed && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
			t.Fatal("negative DSSE retained partial response")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("negative DSSE POST published receipt/audit/job")
	}
}

func TestDSSENativeFixtureUnconfiguredTrustAndExplicitResourceRebinding(t *testing.T) {
	seed := newDSSENativeFixture(t, false)
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: seed.ledger}, dsseObjects: seed.objects}
	v, err := f.VerifyDSSEAttestationSignature(t.Context(), seed.owner.actor, seed.attestation.ID)
	if err != nil || v.ID == "" || v.Result.String() != "not_verified" || len(v.Checks) != 7 {
		t.Fatal("unconfigured DSSE roots assigned trust", v, err)
	}
	for _, check := range v.Checks {
		if check.Result != "not_verified" {
			t.Fatal("unconfigured DSSE policy optimistically passed a check")
		}
	}
	s := &Server{dsseVerification: f, subjectVerification: f}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: seed.base})
	s.bindVerificationCommandFixturePorts(rebound)
	for _, port := range []any{s.dsseVerification, s.subjectVerification} {
		bound, ok := port.(verificationCommandFixture)
		if !ok || bound.ledger != rebound || bound.dsseObjects != seed.objects {
			t.Fatal("rebind lost explicit DSSE objects")
		}
	}
	explicit := &dsseVerificationHTTPFake{}
	s.dsseVerification = explicit
	s.bindDSSEVerificationFixtureResources(seed.objects)
	s.bindVerificationCommandFixturePorts(rebound)
	if s.dsseVerification != explicit {
		t.Fatal("fixture replaced explicit DSSE port")
	}
}
