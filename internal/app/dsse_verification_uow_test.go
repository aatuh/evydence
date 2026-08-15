package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/domain"
)

type failingDSSEVerificationRepository struct{ VerificationRepository }

func (failingDSSEVerificationRepository) InsertVerificationResult(context.Context, domain.VerificationResult) error {
	return errInjectedRepositoryFailure
}

func TestDSSEVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	objectStore := newTestObjectStore()
	ledger.objects = objectStore
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments", "application/json", sampleDigest("dsse-uow-artifact"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, Type: "artifact", Title: "artifact", PayloadHash: sampleDigest("dsse-uow-evidence"), SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: artifact.ID, Digest: artifact.Digest}}}); err != nil {
		t.Fatalf("link artifact to release: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DSSE key: %v", err)
	}
	if _, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey), AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://github.com/actions/runner"}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}}); err != nil {
		t.Fatalf("create DSSE trust root: %v", err)
	}
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"payments","digest":{"sha256":"` + artifact.Digest[len("sha256:"):] + `"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://github.com/actions/workflow","externalParameters":{"mode":"release"}},"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}}}`)
	envelope, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{
			"keyid": "root-1",
			"sig":   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, securedsse.PAE("application/vnd.in-toto+json", payload))),
		}},
	})
	if err != nil {
		t.Fatalf("marshal DSSE envelope: %v", err)
	}
	attestation, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, envelope)
	if err != nil {
		t.Fatalf("upload DSSE attestation: %v", err)
	}
	stagingKey, finalKey, err := CanonicalObjectPayloadKeys(actor.TenantID, attestation.PayloadHash)
	if err != nil {
		t.Fatalf("derive attestation object keys: %v", err)
	}
	if _, err := objectStore.FinalizePayload(ctx, ObjectPayload{TenantID: actor.TenantID, Digest: attestation.PayloadHash, MediaType: "application/vnd.dsse.envelope+json", StagingKey: stagingKey, FinalKey: finalKey}); err != nil {
		t.Fatalf("finalize DSSE attestation: %v", err)
	}

	verification, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, attestation.ID)
	if err != nil {
		t.Fatalf("verify DSSE attestation: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after DSSE verification: %v", err)
	}
	if snapshot.VerificationResults[verification.ID].ID != verification.ID || ledger.verifications[verification.ID].ID != verification.ID {
		t.Fatalf("DSSE verification was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Verification = failingDSSEVerificationRepository{VerificationRepository: repositories.Verification}
		return repositories
	}}
	beforeResults := len(ledger.verifications)
	if _, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, attestation.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed DSSE verification err=%v, want injected repository failure", err)
	}
	if len(ledger.verifications) != beforeResults {
		t.Fatal("failed DSSE verification published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed DSSE verification: %v", err)
	}
	if len(after.VerificationResults) != len(snapshot.VerificationResults) {
		t.Fatalf("failed DSSE verification published durable state: before=%#v after=%#v", snapshot, after)
	}
}
