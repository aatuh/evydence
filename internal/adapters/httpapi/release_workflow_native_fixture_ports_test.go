package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type releaseWorkflowFixtureFacts interface {
	releaseapp.BuildIdentityReader
	releaseapp.BuildCreationGuardReader
	releaseapp.ReleaseStateReader
	releaseapp.ReleaseTransitionGuardReader
	releaseapp.CandidateReleaseReader
	releaseapp.ReleaseCandidateReferenceValidator
	releaseapp.CandidateStateReader
	releaseapp.CandidateTransitionGuardReader
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}
type releaseWorkflowNativeFixture struct {
	catalogCreationNativeFixture
	kind string
}

func (f releaseWorkflowNativeFixture) workflowFacts(ctx context.Context, run func(context.Context, releaseWorkflowFixtureFacts) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.ReleaseCatalog.(releaseWorkflowFixtureFacts)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	})
}
func (f releaseWorkflowNativeFixture) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	var auth application.Authorizer
	var err error
	switch f.kind {
	case "build":
		auth, err = releasequery.NewBuildAuthorizer(f)
	case "candidate":
		auth, err = releasequery.NewCandidateAuthorizer(f)
	default:
		auth = releasequery.NewCatalogAuthorizer()
	}
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, request)
}
func (f releaseWorkflowNativeFixture) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) GetProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	if f.readOnly {
		panic("release replay inspected project metadata")
	}
	var out releasedomain.Project
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildProject(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) GetRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	if f.readOnly {
		panic("release replay inspected release version")
	}
	var out releasedomain.Release
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildRelease(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if f.readOnly {
		panic("release replay inspected artifact digest")
	}
	var out releasedomain.Artifact
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildArtifact(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadBuildCreationScope(ctx context.Context, tenant, project, release string) (releaseapp.BuildCreationCoordinates, error) {
	var out releaseapp.BuildCreationCoordinates
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildCreationScope(ctx, tenant, project, release)
		return err
	})
	if err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadBuildCreationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	var out releasedomain.Artifact
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadBuildCreationArtifact(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadReleaseTransitionScope(ctx context.Context, tenant, id string) (releaseapp.ReleaseTransitionScope, error) {
	var out releaseapp.ReleaseTransitionScope
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadReleaseTransitionScope(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadReleaseState(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	if f.readOnly {
		panic("release replay inspected lifecycle state")
	}
	var out releasedomain.Release
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadReleaseState(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadCandidateRelease(ctx context.Context, tenant, id string) (releaseapp.CandidateReleaseCoordinates, error) {
	var out releaseapp.CandidateReleaseCoordinates
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadCandidateRelease(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ValidateReleaseCandidateReferences(ctx context.Context, tenant, release string, refs releaseapp.ReleaseCandidateReferences) error {
	return f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		return r.ValidateReleaseCandidateReferences(ctx, tenant, release, refs)
	})
}
func (f releaseWorkflowNativeFixture) ReadCandidateTransitionScope(ctx context.Context, tenant, id string) (releaseapp.CandidateTransitionScope, error) {
	var out releaseapp.CandidateTransitionScope
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadCandidateTransitionScope(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) ReadCandidateState(ctx context.Context, tenant, id string) (releaseapp.CandidateStateRow, error) {
	if f.readOnly {
		panic("candidate replay inspected snapshot metadata")
	}
	var out releaseapp.CandidateStateRow
	err := f.workflowFacts(ctx, func(ctx context.Context, r releaseWorkflowFixtureFacts) error {
		var err error
		out, err = r.ReadCandidateState(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.CandidateStateRow{}, err
	}
	return out, nil
}
func (f releaseWorkflowNativeFixture) execute(ctx context.Context, run func(context.Context, releaseWorkflowNativeFixture) error) error {
	return f.transaction(ctx, func(ctx context.Context, bound catalogCreationNativeFixture) error {
		if _, ok := bound.repositories.ReleaseCatalog.(releaseWorkflowFixtureFacts); !ok || bound.repositories.Builds == nil {
			return app.ErrValidation
		}
		current := f
		current.catalogCreationNativeFixture = bound
		return run(ctx, current)
	})
}
func (f releaseWorkflowNativeFixture) ExecuteBuild(ctx context.Context, run func(context.Context, releaseapp.BuildTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx releaseWorkflowNativeFixture) error { return run(ctx, tx) })
}
func (f releaseWorkflowNativeFixture) ExecuteReleaseState(ctx context.Context, run func(context.Context, releaseapp.ReleaseStateTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx releaseWorkflowNativeFixture) error { return run(ctx, tx) })
}
func (f releaseWorkflowNativeFixture) ExecuteCandidateCreation(ctx context.Context, run func(context.Context, releaseapp.CandidateCreationTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx releaseWorkflowNativeFixture) error { return run(ctx, tx) })
}
func (f releaseWorkflowNativeFixture) ExecuteCandidateState(ctx context.Context, run func(context.Context, releaseapp.CandidateStateTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx releaseWorkflowNativeFixture) error { return run(ctx, tx) })
}
func (f releaseWorkflowNativeFixture) InsertBuildRun(ctx context.Context, v releasedomain.BuildRun) error {
	if f.readOnly || f.repositories == nil {
		panic("build replay/unbound write")
	}
	outputs := make([]domain.BuildOutput, 0, len(v.Outputs))
	for _, o := range v.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: o.ArtifactID, Digest: o.Digest})
	}
	return releaseFixtureCoreError(f.repositories.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: v.ID, TenantID: v.TenantID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, CollectorID: v.CollectorID, Provider: v.Provider, CommitSHA: v.CommitSHA, Repository: v.Repository, WorkflowRef: v.WorkflowRef, RunID: v.RunID, RunAttempt: v.RunAttempt, JobID: v.JobID, Actor: v.Actor, Ref: v.Ref, OIDCSubject: v.OIDCSubject, Status: v.Status, StartedAt: v.StartedAt, FinishedAt: v.FinishedAt, ParametersHash: v.ParametersHash, EnvironmentHash: v.EnvironmentHash, SourceIdentity: v.SourceIdentity, Outputs: outputs, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (f releaseWorkflowNativeFixture) UpdateRelease(ctx context.Context, v releasedomain.Release, revision int64, state string) error {
	if f.readOnly || f.repositories == nil {
		panic("release replay/unbound transition")
	}
	if v.Revision != revision+1 {
		return releaseapp.ErrConflict
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.UpdateReleaseState(ctx, domain.ReleaseFromContextModel(v), state))
}
func candidateFixtureRecord(v releasedomain.ReleaseCandidate) domain.ReleaseCandidate {
	return domain.ReleaseCandidate{ID: v.ID, TenantID: v.TenantID, ReleaseID: v.ReleaseID, Name: v.Name, Revision: v.Revision, State: v.State.String(), BuildIDs: v.BuildIDs, ArtifactIDs: v.ArtifactIDs, SBOMIDs: v.SBOMIDs, ScanIDs: v.ScanIDs, VEXIDs: v.VEXIDs, ContractIDs: v.ContractIDs, BundleIDs: v.BundleIDs, SnapshotHash: v.SnapshotHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, PromotedAt: v.PromotedAt, RejectedAt: v.RejectedAt}
}
func (f releaseWorkflowNativeFixture) InsertCandidate(ctx context.Context, v releasedomain.ReleaseCandidate) error {
	if f.readOnly || f.repositories == nil {
		panic("candidate replay/unbound insert")
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, candidateFixtureRecord(v)))
}
func (f releaseWorkflowNativeFixture) UpdateCandidateState(ctx context.Context, v releasedomain.ReleaseCandidate, revision int64, state string) error {
	if f.readOnly || f.repositories == nil {
		panic("candidate replay/unbound transition")
	}
	if v.Revision != revision+1 {
		return releaseapp.ErrConflict
	}
	return releaseFixtureCoreError(f.repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, candidateFixtureRecord(v), state))
}
func (f releaseWorkflowNativeFixture) HashReleaseCandidate(ctx context.Context, v releasedomain.ReleaseCandidate) (string, error) {
	if f.readOnly {
		panic("candidate replay hashed snapshot")
	}
	if ctx == nil {
		return "", releaseapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(candidateFixtureRecord(v))
}
func (f catalogFixtureCommands) nativeWorkflow(readOnly bool, kind string) (releaseWorkflowNativeFixture, application.Clock, application.IDGenerator) {
	ports, clock, ids := f.nativeCatalog(readOnly)
	return releaseWorkflowNativeFixture{catalogCreationNativeFixture: ports, kind: kind}, clock, ids
}
func (f lifecycleFixtureCommands) nativeReleaseState(readOnly bool) (*releaseapp.ReleaseStateCommands, error) {
	ports, clock, ids := f.nativeWorkflow(readOnly, "release")
	return releaseapp.NewReleaseStateCommands(releaseapp.ReleaseStateCommandConfig{Reader: ports, Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
func (f registrationFixtureCommands) nativeBuild(readOnly bool) (*releaseapp.BuildCommands, error) {
	ports, clock, ids := f.nativeWorkflow(readOnly, "build")
	return releaseapp.NewBuildCommands(releaseapp.BuildCommandConfig{Reader: ports, Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
func (f registrationFixtureCommands) nativeCandidate(readOnly bool) (*releaseapp.CandidateCommands, error) {
	ports, clock, ids := f.nativeWorkflow(readOnly, "candidate")
	return releaseapp.NewCandidateCommands(releaseapp.CandidateCommandConfig{Transactions: ports, Authorizer: ports, Canonicalizer: ports, Clock: clock, IDs: ids})
}
func (f lifecycleFixtureCommands) nativeCandidateState(readOnly bool) (*releaseapp.CandidateStateCommands, error) {
	ports, clock, ids := f.nativeWorkflow(readOnly, "release")
	return releaseapp.NewCandidateStateCommands(releaseapp.CandidateStateCommandConfig{Transactions: ports, Authorizer: ports, Clock: clock, IDs: ids})
}
