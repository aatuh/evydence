package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type memoryAttestationTestReader interface {
	releaseapp.BuildAttestationSnapshotReader
	releaseapp.BuildAttestationCreationGuardReader
}

func TestMemoryAttestationScopeIsCurrentOwnedAndExcludesCanonicalMetadataAndDigests(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Builds.(memoryAttestationTestReader)
	if !ok {
		t.Fatal("memory builds lack focused attestation reads")
	}
	b := domain.BuildRun{ID: "b", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", SourceIdentity: map[string]any{"bad": make(chan int)}, Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: strings.Repeat("private", 10000)}}}
	tx.state.BuildRuns[b.ID] = b
	v, err := r.ReadBuildAttestationCreationScope(t.Context(), "tenant", b.ID)
	if err != nil || v.BuildID != b.ID || v.ProductID != "tenant-product" || v.ReleaseProductID != "tenant-product" || !reflect.DeepEqual(v.ArtifactIDs, []string{"artifact"}) {
		t.Fatal("attestation guard read source identity/digests or lost current scope", err)
	}
	if v, err := r.ReadBuildAttestationCreationScope(t.Context(), "foreign", b.ID); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, releaseapp.BuildAttestationCreationCoordinates{}) {
		t.Fatal("attestation guard crossed tenant boundary", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ReadBuildAttestationCreationScope(ctx, "tenant", b.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, releaseapp.BuildAttestationCreationCoordinates{}) {
		t.Fatal("cancelled attestation guard returned identity", err)
	}
	b.Outputs = make([]domain.BuildOutput, 4097)
	tx.state.BuildRuns[b.ID] = b
	if v, err := r.ReadBuildAttestationCreationScope(t.Context(), "tenant", b.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, releaseapp.BuildAttestationCreationCoordinates{}) {
		t.Fatal("attestation output row overflow returned partial identity", err)
	}
}

func TestMemoryBuildSnapshotPreservesExactSourceIdentityAcrossInsertCommitAndRead(t *testing.T) {
	factory, tx := memoryMembershipReadFixture(t)
	b := domain.BuildRun{ID: "b", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: fixedNow(), CreatedAt: fixedNow(), SourceIdentity: map[string]any{"sequence": json.Number("9007199254740993")}, SchemaVersion: domain.BuildRunSchemaVersion}
	if err := tx.Repositories().Builds.InsertBuildRun(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(s.BuildRuns[b.ID].SourceIdentity, b.SourceIdentity) {
		t.Fatal("immutable build identity rounded at commit", err)
	}
	u, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Rollback(t.Context()) }()
	r, ok := u.Repositories().Builds.(memoryAttestationTestReader)
	if !ok {
		t.Fatal("focused attestation snapshot missing")
	}
	v, err := r.ReadBuildAttestationBuild(t.Context(), "tenant", b.ID)
	if err != nil || !reflect.DeepEqual(v.SourceIdentity, b.SourceIdentity) {
		t.Fatal("attestation read changed exact build identity", err)
	}
	v.SourceIdentity["sequence"] = "changed"
	last, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(last.BuildRuns[b.ID].SourceIdentity, b.SourceIdentity) {
		t.Fatal("returned build shared source identity", err)
	}
}
