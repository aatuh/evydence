package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingDSSEVerificationRepository struct{ VerificationRepository }

func (failingDSSEVerificationRepository) InsertVerificationResult(context.Context, domain.VerificationResult) error {
	return errInjectedRepositoryFailure
}

type dsseVerificationObjectStore struct{ objects map[string]Object }

func (s *dsseVerificationObjectStore) Put(_ context.Context, object Object) error {
	s.objects[object.Key] = object
	return nil
}

func (s *dsseVerificationObjectStore) Get(_ context.Context, key string) (Object, error) {
	object, ok := s.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	return object, nil
}

func TestDSSEVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	objectStore := &dsseVerificationObjectStore{objects: map[string]Object{}}
	ledger.objects = objectStore
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DSSE key: %v", err)
	}
	if _, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}); err != nil {
		t.Fatalf("create DSSE trust root: %v", err)
	}
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	envelope, err := json.Marshal(map[string]any{
		"payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{
			"keyid": "root-1",
			"sig":   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		}},
	})
	if err != nil {
		t.Fatalf("marshal DSSE envelope: %v", err)
	}
	objectKey := "tenants/" + actor.TenantID + "/raw/dsse-attestation.json"
	if err := objectStore.Put(ctx, Object{Key: objectKey, Bytes: envelope}); err != nil {
		t.Fatalf("put DSSE envelope: %v", err)
	}
	attestation := domain.BuildAttestation{ID: "att_dsse_uow", TenantID: actor.TenantID, PayloadRef: "object://" + objectKey, PayloadHash: sampleDigest("dsse-attestation")}
	ledger.attestations[attestation.ID] = attestation

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
