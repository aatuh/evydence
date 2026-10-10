package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Local test setup uses the same scoped replay clone as the creation ports;
// production lifecycle and ingestion handlers have only focused dependencies.
type lifecycleFixtureCommands struct{ catalogFixtureCommands }

func (f lifecycleFixtureCommands) AuthorizeReleaseTransition(ctx context.Context, actor identitydomain.Actor, id string) error {
	c, err := f.nativeReleaseState(true)
	if err != nil {
		return err
	}
	return mapReleaseStateCommandError(c.AuthorizeReleaseTransition(ctx, actor, id))
}

func (f lifecycleFixtureCommands) FreezeRelease(ctx context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	c, err := f.nativeReleaseState(false)
	if err != nil {
		return releasedomain.Release{}, err
	}
	value, err := c.FreezeRelease(ctx, actor, id, revision)
	return value, mapReleaseStateCommandError(err)
}

func (f lifecycleFixtureCommands) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	c, err := f.nativeReleaseState(false)
	if err != nil {
		return releasedomain.Release{}, err
	}
	value, err := c.ApproveRelease(ctx, actor, id, revision)
	return value, mapReleaseStateCommandError(err)
}

func (f lifecycleFixtureCommands) AuthorizeCandidateTransition(ctx context.Context, actor identitydomain.Actor, id string) error {
	c, err := f.nativeCandidateState(true)
	if err != nil {
		return err
	}
	return mapReleaseStateCommandError(c.AuthorizeCandidateTransition(ctx, actor, id))
}

func (f lifecycleFixtureCommands) UpdateReleaseCandidateState(ctx context.Context, actor identitydomain.Actor, id, state, reason string, revision int64) (releasedomain.ReleaseCandidate, error) {
	c, err := f.nativeCandidateState(false)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	value, err := c.UpdateReleaseCandidateState(ctx, actor, id, state, reason, revision)
	return value, mapReleaseStateCommandError(err)
}

func (f lifecycleFixtureCommands) AuthorizeBuildAttestationCreation(ctx context.Context, actor identitydomain.Actor, id string) error {
	c, err := f.nativeAttestation(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeBuildAttestationCreation(ctx, actor, id))
}

func (f lifecycleFixtureCommands) UploadBuildAttestation(ctx context.Context, actor identitydomain.Actor, id string, raw []byte) (releasedomain.BuildAttestation, error) {
	c, err := f.nativeAttestation(false)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	value, err := c.UploadBuildAttestation(ctx, actor, id, raw)
	return value, mapBuildAttestationCommandError(err)
}

func (s *Server) bindLifecycleFixturePorts(ledger *app.Ledger) {
	commands := lifecycleFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.releaseStateCommands.(lifecycleFixtureCommands); s.releaseStateCommands == nil || fixture {
		s.releaseStateCommands = commands
	}
	if _, fixture := s.candidateStateCommands.(lifecycleFixtureCommands); s.candidateStateCommands == nil || fixture {
		s.candidateStateCommands = commands
	}
	if _, fixture := s.buildAttestationCommands.(lifecycleFixtureCommands); s.buildAttestationCommands == nil || fixture {
		s.buildAttestationCommands = commands
	}
}

var (
	_ ReleaseStateCommands     = lifecycleFixtureCommands{}
	_ CandidateStateCommands   = lifecycleFixtureCommands{}
	_ BuildAttestationCommands = lifecycleFixtureCommands{}
)
