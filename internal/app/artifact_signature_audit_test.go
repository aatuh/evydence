package app

import (
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestArtifactSignatureCreationRecordsHumanAuditIdentity(t *testing.T) {
	for _, transactional := range []bool{true, false} {
		name := "maps"
		if transactional {
			name = "memory_transaction"
		}
		t.Run(name, func(t *testing.T) {
			memory := NewMemoryUnitOfWorkFactory()
			ledger, _, owner := newReleaseEvidenceUnitOfWorkFixture(t, memory)
			artifact, err := ledger.RegisterArtifact(t.Context(), owner, "api.tar", "application/octet-stream", sampleDigest("human-signature-audit"), 1)
			if err != nil {
				t.Fatal(err)
			}
			if !transactional {
				ledger.unitOfWork = nil
			}
			human := domain.Actor{TenantID: owner.TenantID, UserID: "reviewer", Scopes: []string{ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.TenantID, Scopes: []string{ScopeEvidenceWrite}}}}
			before := len(ledger.chain[owner.TenantID])
			signature, err := ledger.CreateArtifactSignature(t.Context(), human, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "recorded"})
			if err != nil {
				t.Fatal("human signature creation:", err)
			}
			entries := ledger.chain[owner.TenantID][before:]
			if transactional {
				snapshot, err := memory.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				entries = snapshot.AuditEntries[owner.TenantID][before:]
			}
			if len(entries) != 1 {
				t.Fatal("signature did not append exactly one audit")
			}
			entry := entries[0]
			if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.SubjectID != signature.ID || entry.EntryType != "artifact_signature.created" || entry.PayloadHash != artifact.Digest || signature.VerificationStatus != "recorded" {
				t.Fatal("signature lost actual principal/digest-bound recording semantics", entry)
			}
		})
	}
}
