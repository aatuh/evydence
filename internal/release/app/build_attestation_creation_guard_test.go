package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type attestationGuardFake struct {
	*buildGuardFake
	scope            BuildAttestationCreationCoordinates
	runs, buildReads int
}

func (f *attestationGuardFake) ExecuteBuildAttestation(ctx context.Context, fn func(context.Context, BuildAttestationTransaction) error) error {
	f.runs++
	return fn(ctx, f)
}
func (f *attestationGuardFake) ReadBuildAttestationCreationScope(context.Context, string, string) (BuildAttestationCreationCoordinates, error) {
	f.buildReads++
	return f.scope, f.err
}
func (*attestationGuardFake) GetBuildRun(context.Context, string, string) (releasedomain.BuildRun, error) {
	panic("guard materialized build metadata")
}
func (*attestationGuardFake) WriteBuildAttestationEvidence(context.Context, identitydomain.Actor, BuildAttestationEvidenceInput) (BuildAttestationEvidenceReceipt, error) {
	panic("guard wrote evidence")
}
func (*attestationGuardFake) InsertBuildAttestation(context.Context, releasedomain.BuildAttestation) error {
	panic("guard inserted attestation")
}
func (*attestationGuardFake) EnqueueOutbox(context.Context, application.OutboxEvent) error {
	panic("guard enqueued job")
}

type guardPanicAttestationParser struct{}

func (guardPanicAttestationParser) ParseBuildAttestation(context.Context, BuildAttestationPayloadSource) (ParsedBuildAttestation, error) {
	panic("guard parsed payload")
}

type guardPanicAttestationStager struct{}

func (guardPanicAttestationStager) StageBuildAttestationPayload(context.Context, string, BuildAttestationPayloadSource) (StagedBuildAttestationPayload, error) {
	panic("guard staged payload")
}

func TestBuildAttestationCreationGuardNeverReadsMetadataOrRunsIngestion(t *testing.T) {
	f := &attestationGuardFake{buildGuardFake: &buildGuardFake{artifact: releasedomain.Artifact{ID: "artifact", TenantID: "tenant"}}, scope: BuildAttestationCreationCoordinates{BuildCreationCoordinates: BuildCreationCoordinates{TenantID: "tenant", ProjectID: "project", ProductID: "product", ReleaseID: "release", ReleaseProductID: "product"}, BuildID: "build", ArtifactIDs: []string{"artifact", "artifact", ""}}}
	s, err := NewBuildAttestationCommands(BuildAttestationCommandConfig{Reader: f, Transactions: f, Authorizer: f, AttestationParser: guardPanicAttestationParser{}, PayloadStager: guardPanicAttestationStager{}, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{ScopeBuildWrite}}
	if err := s.AuthorizeBuildAttestationCreation(t.Context(), a, " build "); err != nil || f.buildReads != 1 || f.artifactReads != 1 || f.authorizations != 4 {
		t.Fatal("guard skipped or repeated current coordinates", err, f)
	}
	f.denied = true
	before := f.buildReads
	if err := s.AuthorizeBuildAttestationCreation(t.Context(), a, "build"); !errors.Is(err, application.ErrForbidden) || f.buildReads != before+1 {
		t.Fatal("denied current parents accepted", err)
	}
	f.denied = false
	f.artifact.TenantID = "other"
	if err := s.AuthorizeBuildAttestationCreation(t.Context(), a, "build"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign output accepted", err)
	}
	f.scope.ReleaseProductID = "other"
	if err := s.AuthorizeBuildAttestationCreation(t.Context(), a, "build"); !errors.Is(err, ErrNotFound) {
		t.Fatal("incoherent parent accepted", err)
	}
	f.scope.ReleaseProductID = "product"
	for _, id := range []string{strings.Repeat(" ", 1025) + "build", "bad\x00id", string([]byte{0xff})} {
		before := f.runs
		if err := s.AuthorizeBuildAttestationCreation(t.Context(), a, id); !errors.Is(err, ErrValidation) || f.runs != before {
			t.Fatal("raw ID reached transaction", err)
		}
		if _, err := s.UploadBuildAttestation(t.Context(), a, id, []byte("raw")); !errors.Is(err, ErrValidation) {
			t.Fatal("fresh ID reached metadata reader", err)
		}
	}
}
