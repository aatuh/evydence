package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func TestMemoryCollectorReleaseReferenceUsesCurrentSignatureAndArtifactDigest(t *testing.T) {
	tx, _, signature := memoryArtifactSignatureFixture(t)
	reader, ok := tx.Repositories().Builds.(interface {
		ReadCollectorReleaseReference(context.Context, string, string, string) (integrationapp.CollectorReference, error)
	})
	if !ok {
		t.Fatal("memory builds lacks current collector release references")
	}
	v, err := reader.ReadCollectorReleaseReference(t.Context(), "tenant", "signature", signature.ID)
	if err != nil || v != (integrationapp.CollectorReference{ID: signature.ID, TenantID: "tenant", Type: "signature", Digest: signature.SubjectDigest}) {
		t.Fatal("signature reference lost owned digest", err)
	}
	a := tx.state.Artifacts[signature.ArtifactID]
	a.Digest = "changed"
	tx.state.Artifacts[a.ID] = a
	if _, err := reader.ReadCollectorReleaseReference(t.Context(), "tenant", "signature", signature.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale artifact digest accepted", err)
	}
	tx.state.Collectors["collector"] = domain.Collector{ID: "collector", TenantID: "foreign"}
	if _, err := reader.ReadCollectorReleaseReference(t.Context(), "tenant", "collector", "collector"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign collector accepted", err)
	}
}
