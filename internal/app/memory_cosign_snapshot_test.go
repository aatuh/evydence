package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestMemoryCosignSnapshotUsesCurrentOwnedCoordinatesAndNoDetachedSignatureText(t *testing.T) {
	tx, _, signature := memoryArtifactSignatureFixture(t)
	reader, ok := tx.Repositories().Verification.(verificationapp.CosignSnapshotReader)
	if !ok {
		t.Fatal("memory verification lacks native Cosign snapshot reader")
	}
	locker, ok := tx.Repositories().Verification.(verificationapp.CosignVerificationScopeLocker)
	if !ok {
		t.Fatal("memory verification lacks flat Cosign scope reader")
	}
	signature.Signature = strings.Repeat("unselected", 100000)
	tx.state.ArtifactSignatures[signature.ID] = signature
	tx.state.ContainerImages["b"] = domain.ContainerImage{ID: "b", TenantID: "tenant", ArtifactID: signature.ArtifactID, Digest: signature.SubjectDigest}
	tx.state.ContainerImages["a"] = domain.ContainerImage{ID: "a", TenantID: "tenant", ArtifactID: signature.ArtifactID, Digest: signature.SubjectDigest}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := locker.LockCosignVerificationScope(t.Context(), "tenant", signature.ID)
	if err != nil || refs != (application.ResourceReferences{ArtifactID: signature.ArtifactID}) {
		t.Fatal("scope lost current ownership", refs, err)
	}
	subject, err := reader.ResolveCosignSubject(t.Context(), "tenant", signature.ID)
	if err != nil || subject.ArtifactID != signature.ArtifactID || subject.ContainerImageID != "a" || subject.SubjectDigest != signature.SubjectDigest || subject.Resources != refs {
		t.Fatal("subject lost digest/selected image identity", subject, err)
	}
	v, err := reader.ReadCosignSnapshot(t.Context(), subject)
	if err != nil || v.Subject != subject || v.Algorithm != signature.Algorithm || v.ArtifactDigest != signature.SubjectDigest || v.PayloadHash != signature.PayloadHash || v.PayloadFinalized {
		t.Fatal("snapshot changed metadata or trusted missing payload", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("Cosign reads mutated repository")
	}
	signature.SubjectDigest = strings.Repeat("x", 1025)
	tx.state.ArtifactSignatures[signature.ID] = signature
	if _, err := locker.LockCosignVerificationScope(t.Context(), "tenant", signature.ID); err != nil {
		t.Fatal("flat scope hydrated unselected digest", err)
	}
	if _, err := reader.ResolveCosignSubject(t.Context(), "tenant", signature.ID); err == nil {
		t.Fatal("oversized selected digest accepted")
	}
}
