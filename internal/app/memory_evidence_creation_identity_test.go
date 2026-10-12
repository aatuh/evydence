package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryEvidenceCreationArtifactGuardReadsIdentityOnlyAndRejectsForeignState(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Evidence.(interface {
		LockCreationArtifactIdentity(context.Context, string, string) error
	})
	if !ok {
		t.Fatal("evidence repository lacks creation artifact identity guard")
	}
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant", Name: strings.Repeat("unselected", 10000), Digest: "unselected-invalid-digest"}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.LockCreationArtifactIdentity(t.Context(), "tenant", "artifact"); err != nil {
		t.Fatal("identity guard read descriptive metadata/digest", err)
	}
	if err := reader.LockCreationArtifactIdentity(t.Context(), "foreign", "artifact"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign artifact identity accepted", err)
	}
	if err := reader.LockCreationArtifactIdentity(t.Context(), "tenant", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing artifact identity accepted", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("artifact identity guard changed state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.LockCreationArtifactIdentity(ctx, "tenant", "artifact"); !errors.Is(err, context.Canceled) {
		t.Fatal("identity guard ignored cancellation", err)
	}
}
