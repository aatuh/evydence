package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// These test-only ports preserve fixture state while release-write handlers
// shed the legacy transport interface. They share the scoped replay clone.
type registrationFixtureCommands struct{ catalogFixtureCommands }

func localBuildCreationInput(in releaseapp.CreateBuildRunInput) app.CreateBuildRunInput {
	outputs := make([]domain.BuildOutput, 0, len(in.Outputs))
	for _, out := range in.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: out.ArtifactID, Digest: out.Digest})
	}
	return app.CreateBuildRunInput{ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Provider: in.Provider, CommitSHA: in.CommitSHA, Repository: in.Repository, WorkflowRef: in.WorkflowRef, RunID: in.RunID, RunAttempt: in.RunAttempt, JobID: in.JobID, GitHubActor: in.GitHubActor, Ref: in.Ref, OIDCSubject: in.OIDCSubject, Status: in.Status, StartedAt: in.StartedAt, FinishedAt: in.FinishedAt, ParametersHash: in.ParametersHash, EnvironmentHash: in.EnvironmentHash, ProviderMetadata: in.ProviderMetadata, Outputs: outputs}
}

func candidateLocalInput(in releaseapp.CreateReleaseCandidateInput) app.CreateReleaseCandidateInput {
	return app.CreateReleaseCandidateInput{ReleaseID: in.ReleaseID, Name: in.Name, BuildIDs: in.BuildIDs, ArtifactIDs: in.ArtifactIDs, SBOMIDs: in.SBOMIDs, ScanIDs: in.ScanIDs, VEXIDs: in.VEXIDs, ContractIDs: in.ContractIDs, BundleIDs: in.BundleIDs}
}

func (f registrationFixtureCommands) AuthorizeArtifactRegistration(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterArtifactInput) error {
	return f.commandLedger(ctx).AuthorizeArtifactRegistration(ctx, actor, input)
}

func (f registrationFixtureCommands) RegisterArtifact(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterArtifactInput) (releasedomain.Artifact, error) {
	value, err := f.commandLedger(ctx).RegisterArtifact(ctx, actor, input.Name, input.MediaType, input.Digest, input.Size)
	return artifactFixtureModel(value), err
}

func (f registrationFixtureCommands) AuthorizeContainerImageRegistration(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterContainerImageInput) error {
	return f.commandLedger(ctx).AuthorizeContainerImageRegistration(ctx, actor, input)
}

func (f registrationFixtureCommands) RegisterContainerImage(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterContainerImageInput) (releasedomain.ContainerImage, error) {
	value, err := f.commandLedger(ctx).RegisterContainerImage(ctx, actor, app.RegisterContainerImageInput{ArtifactID: input.ArtifactID, Repository: input.Repository, Tag: input.Tag, Digest: input.Digest, Platform: input.Platform})
	return releasedomain.ContainerImage{ID: value.ID, TenantID: value.TenantID, ArtifactID: value.ArtifactID, Repository: value.Repository, Tag: value.Tag, Digest: value.Digest, Platform: value.Platform, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}, err
}

func (f registrationFixtureCommands) AuthorizeBuildCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateBuildRunInput) error {
	return f.commandLedger(ctx).AuthorizeBuildCreation(ctx, actor, input)
}

func (f registrationFixtureCommands) CreateBuildRun(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateBuildRunInput) (releasedomain.BuildRun, error) {
	value, err := f.commandLedger(ctx).CreateBuildRun(ctx, actor, localBuildCreationInput(input))
	return buildFixtureModel(value), err
}

func (f registrationFixtureCommands) AuthorizeCandidateCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseCandidateInput) error {
	return f.commandLedger(ctx).AuthorizeCandidateCreation(ctx, actor, input)
}

func (f registrationFixtureCommands) CreateReleaseCandidate(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error) {
	value, err := f.commandLedger(ctx).CreateReleaseCandidate(ctx, actor, candidateLocalInput(input))
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidateFixtureModel(value)
}

func (s *Server) bindRegistrationFixturePorts(ledger *app.Ledger) {
	commands := registrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.artifactCommands.(registrationFixtureCommands); s.artifactCommands == nil || fixture {
		s.artifactCommands = commands
	}
	if _, fixture := s.containerImageCommands.(registrationFixtureCommands); s.containerImageCommands == nil || fixture {
		s.containerImageCommands = commands
	}
	if _, fixture := s.buildCommands.(registrationFixtureCommands); s.buildCommands == nil || fixture {
		s.buildCommands = commands
	}
	if _, fixture := s.candidateCommands.(registrationFixtureCommands); s.candidateCommands == nil || fixture {
		s.candidateCommands = commands
	}
}

var (
	_ ArtifactCommands       = registrationFixtureCommands{}
	_ ContainerImageCommands = registrationFixtureCommands{}
	_ BuildCommands          = registrationFixtureCommands{}
	_ CandidateCommands      = registrationFixtureCommands{}
)
