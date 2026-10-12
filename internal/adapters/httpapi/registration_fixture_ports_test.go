package httpapi

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// These test-only ports preserve fixture state while release-write handlers
// shed the legacy transport interface. They share the scoped replay clone.
type registrationFixtureCommands struct{ catalogFixtureCommands }

func (f registrationFixtureCommands) AuthorizeArtifactRegistration(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterArtifactInput) error {
	c, err := f.nativeArtifact(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeArtifactRegistration(ctx, actor, input))
}

func (f registrationFixtureCommands) RegisterArtifact(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterArtifactInput) (releasedomain.Artifact, error) {
	c, err := f.nativeArtifact(false)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	value, err := c.RegisterArtifact(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (f registrationFixtureCommands) AuthorizeContainerImageRegistration(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterContainerImageInput) error {
	c, err := f.nativeImage(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeContainerImageRegistration(ctx, actor, input))
}

func (f registrationFixtureCommands) RegisterContainerImage(ctx context.Context, actor identitydomain.Actor, input releaseapp.RegisterContainerImageInput) (releasedomain.ContainerImage, error) {
	c, err := f.nativeImage(false)
	if err != nil {
		return releasedomain.ContainerImage{}, err
	}
	value, err := c.RegisterContainerImage(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (f registrationFixtureCommands) AuthorizeBuildCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateBuildRunInput) error {
	c, err := f.nativeBuild(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeBuildCreation(ctx, actor, input))
}

func (f registrationFixtureCommands) CreateBuildRun(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateBuildRunInput) (releasedomain.BuildRun, error) {
	c, err := f.nativeBuild(false)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	value, err := c.CreateBuildRun(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (f registrationFixtureCommands) AuthorizeCandidateCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseCandidateInput) error {
	c, err := f.nativeCandidate(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeCandidateCreation(ctx, actor, input))
}

func (f registrationFixtureCommands) CreateReleaseCandidate(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error) {
	c, err := f.nativeCandidate(false)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	value, err := c.CreateReleaseCandidate(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (s *Server) bindRegistrationFixturePorts(ledger *repositoryFixture) {
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
