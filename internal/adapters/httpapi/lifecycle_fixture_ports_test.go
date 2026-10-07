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
	return f.commandLedger(ctx).AuthorizeReleaseTransition(ctx, actor, id)
}

func (f lifecycleFixtureCommands) FreezeRelease(ctx context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	value, err := f.commandLedger(ctx).FreezeRelease(ctx, actor, id, revision)
	if err != nil {
		return releasedomain.Release{}, err
	}
	return releaseFixtureModel(value)
}

func (f lifecycleFixtureCommands) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, revision int64) (releasedomain.Release, error) {
	value, err := f.commandLedger(ctx).ApproveRelease(ctx, actor, id, revision)
	if err != nil {
		return releasedomain.Release{}, err
	}
	return releaseFixtureModel(value)
}

func (f lifecycleFixtureCommands) AuthorizeCandidateTransition(ctx context.Context, actor identitydomain.Actor, id string) error {
	return f.commandLedger(ctx).AuthorizeCandidateTransition(ctx, actor, id)
}

func (f lifecycleFixtureCommands) UpdateReleaseCandidateState(ctx context.Context, actor identitydomain.Actor, id, state, reason string, revision int64) (releasedomain.ReleaseCandidate, error) {
	value, err := f.commandLedger(ctx).UpdateReleaseCandidateState(ctx, actor, id, state, reason, revision)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidateFixtureModel(value)
}

func (f lifecycleFixtureCommands) AuthorizeBuildAttestationCreation(ctx context.Context, actor identitydomain.Actor, id string) error {
	return f.commandLedger(ctx).AuthorizeBuildAttestationCreation(ctx, actor, id)
}

func (f lifecycleFixtureCommands) UploadBuildAttestation(ctx context.Context, actor identitydomain.Actor, id string, raw []byte) (releasedomain.BuildAttestation, error) {
	value, err := f.commandLedger(ctx).UploadBuildAttestation(ctx, actor, id, raw)
	return releasedomain.BuildAttestation{ID: value.ID, TenantID: value.TenantID, BuildID: value.BuildID, EvidenceID: value.EvidenceID, PayloadRef: value.PayloadRef, PayloadHash: value.PayloadHash, PayloadSize: value.PayloadSize, PayloadType: value.PayloadType, PredicateType: value.PredicateType, SubjectDigests: value.SubjectDigests, BuilderID: value.BuilderID, BuildType: value.BuildType, MaterialsCount: value.MaterialsCount, SignatureCount: value.SignatureCount, VerificationStatus: value.VerificationStatus, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}, err
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
