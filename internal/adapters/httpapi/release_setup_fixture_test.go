package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// Setup uses the same focused commands as the handlers, never aggregate
// mutation facades. Object resources must be passed explicitly where needed.
type releaseSetupFixture struct {
	catalogFixtureCommands
	objects app.ObjectStore
}

func releaseSetup(ledger *repositoryFixture) releaseSetupFixture {
	return releaseSetupFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
}
func (f releaseSetupFixture) CreateProduct(ctx context.Context, a domain.Actor, name, slug string) (domain.Product, error) {
	v, err := f.catalogFixtureCommands.CreateProduct(ctx, a, releaseapp.CreateProductInput{Name: name, Slug: slug})
	return domain.Product{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, CreatedAt: v.CreatedAt}, err
}
func (f releaseSetupFixture) CreateProject(ctx context.Context, a domain.Actor, product, name string) (domain.Project, error) {
	v, err := f.catalogFixtureCommands.CreateProject(ctx, a, releaseapp.CreateProjectInput{ProductID: product, Name: name})
	return domain.Project{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, CreatedAt: v.CreatedAt}, err
}
func (f releaseSetupFixture) CreateRelease(ctx context.Context, a domain.Actor, product, version string) (domain.Release, error) {
	v, err := f.catalogFixtureCommands.CreateRelease(ctx, a, releaseapp.CreateReleaseInput{ProductID: product, Version: version})
	return domain.ReleaseFromContextModel(v), err
}
func (f releaseSetupFixture) RegisterArtifact(ctx context.Context, a domain.Actor, name, media, digest string, size int64) (domain.Artifact, error) {
	v, err := (registrationFixtureCommands{f.catalogFixtureCommands}).RegisterArtifact(ctx, a, releaseapp.RegisterArtifactInput{Name: name, MediaType: media, Digest: digest, Size: size})
	return domain.Artifact{ID: v.ID, TenantID: v.TenantID, Name: v.Name, MediaType: v.MediaType, Digest: v.Digest, Size: v.Size, CreatedAt: v.CreatedAt}, err
}
func (f releaseSetupFixture) CreateBuildRun(ctx context.Context, a domain.Actor, in releaseapp.CreateBuildRunInput) (domain.BuildRun, error) {
	v, err := (registrationFixtureCommands{f.catalogFixtureCommands}).CreateBuildRun(ctx, a, in)
	if err != nil {
		return domain.BuildRun{}, err
	}
	outputs := make([]domain.BuildOutput, 0, len(v.Outputs))
	for _, o := range v.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: o.ArtifactID, Digest: o.Digest})
	}
	return domain.BuildRun{ID: v.ID, TenantID: v.TenantID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, CollectorID: v.CollectorID,
		Provider: v.Provider, CommitSHA: v.CommitSHA, Repository: v.Repository, WorkflowRef: v.WorkflowRef, RunID: v.RunID,
		RunAttempt: v.RunAttempt, JobID: v.JobID, Actor: v.Actor, Ref: v.Ref, OIDCSubject: v.OIDCSubject, Status: v.Status,
		StartedAt: v.StartedAt, FinishedAt: v.FinishedAt, ParametersHash: v.ParametersHash, EnvironmentHash: v.EnvironmentHash,
		SourceIdentity: v.SourceIdentity, Outputs: outputs, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, nil
}
func (f releaseSetupFixture) CreateReleaseCandidate(ctx context.Context, a domain.Actor, in releaseapp.CreateReleaseCandidateInput) (domain.ReleaseCandidate, error) {
	v, err := (registrationFixtureCommands{f.catalogFixtureCommands}).CreateReleaseCandidate(ctx, a, in)
	if err != nil {
		return domain.ReleaseCandidate{}, err
	}
	return candidateFixtureRecord(v), nil
}
func (f releaseSetupFixture) UploadBuildAttestation(ctx context.Context, a domain.Actor, build string, raw []byte) (domain.BuildAttestation, error) {
	c, err := (lifecycleFixtureCommands{f.catalogFixtureCommands}).nativeAttestationWithObjects(false, f.objects)
	if err != nil {
		return domain.BuildAttestation{}, err
	}
	v, err := c.UploadBuildAttestation(ctx, a, build, raw)
	if err != nil {
		return domain.BuildAttestation{}, mapBuildAttestationCommandError(err)
	}
	return domain.BuildAttestation{ID: v.ID, TenantID: v.TenantID, BuildID: v.BuildID, EvidenceID: v.EvidenceID,
		PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, PayloadType: v.PayloadType,
		PredicateType: v.PredicateType, SubjectDigests: v.SubjectDigests, BuilderID: v.BuilderID, BuildType: v.BuildType,
		MaterialsCount: v.MaterialsCount, SignatureCount: v.SignatureCount, VerificationStatus: v.VerificationStatus,
		SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, nil
}
