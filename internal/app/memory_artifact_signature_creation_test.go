package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestMemoryArtifactSignatureCreationReadsCurrentScopeWithoutDescriptiveMetadata(t *testing.T) {
	tx, _, artifact := memoryArtifactQueryFixture(t)
	reader, ok := tx.Repositories().SupplyChain.(verificationapp.ArtifactSignatureCreationReader)
	if !ok {
		t.Fatal("memory supply chain lacks focused signature creation reader")
	}
	grants, ok := tx.Repositories().SupplyChain.(releasequery.ArtifactPointReader)
	if !ok {
		t.Fatal("memory supply chain lacks metadata-free artifact grants")
	}
	artifact.Name, artifact.MediaType, artifact.Size = strings.Repeat("private", 10000), strings.Repeat("private", 10000), -1
	tx.state.Artifacts[artifact.ID] = artifact
	ref, err := reader.LockArtifactSignatureCreationScope(t.Context(), "tenant", artifact.ID)
	if err != nil || ref != (application.ResourceReferences{ArtifactID: artifact.ID}) {
		t.Fatal("scope reader selected descriptive metadata or lost ownership", ref, err)
	}
	point, err := grants.GetArtifactPoint(t.Context(), releasequery.ArtifactReadRequest{TenantID: "tenant", ID: artifact.ID, TenantWide: true})
	if err != nil || !point.Visible || point.Artifact.Name != "" || point.Artifact.Digest != "" {
		t.Fatal("grant reader exposed or validated descriptive/digest projection", err)
	}
	v, err := reader.LockSignatureArtifact(t.Context(), "tenant", artifact.ID)
	if err != nil || v != (verificationapp.SignatureArtifact{ID: artifact.ID, TenantID: "tenant", Digest: artifact.Digest}) {
		t.Fatal("signature reader lost current declared digest", v, err)
	}
	artifact.Digest = strings.Repeat("x", 1025)
	tx.state.Artifacts[artifact.ID] = artifact
	if _, err := reader.LockArtifactSignatureCreationScope(t.Context(), "tenant", artifact.ID); err != nil {
		t.Fatal("scope reader hydrated unselected digest", err)
	}
	if _, err := reader.LockSignatureArtifact(t.Context(), "tenant", artifact.ID); err == nil {
		t.Fatal("oversized selected digest was accepted")
	}
	if _, err := reader.LockArtifactSignatureCreationScope(t.Context(), "foreign", artifact.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign artifact scope accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.LockSignatureArtifact(ctx, "tenant", artifact.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated", err)
	}
}
