package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingBuildRepository struct{ BuildRepository }

type failingSupplyChainRepository struct{ SupplyChainRepository }

type failingSourceRepository struct{ SourceRepository }

func (failingBuildRepository) InsertBuildRun(context.Context, domain.BuildRun) error {
	return errInjectedRepositoryFailure
}

func (failingBuildRepository) InsertCollector(context.Context, domain.Collector) error {
	return errInjectedRepositoryFailure
}

func (failingBuildRepository) InsertCollectorRelease(context.Context, domain.CollectorRelease) error {
	return errInjectedRepositoryFailure
}

func (failingBuildRepository) InsertBuildAttestation(context.Context, domain.BuildAttestation) error {
	return errInjectedRepositoryFailure
}

func (failingSupplyChainRepository) InsertContainerImage(context.Context, domain.ContainerImage) error {
	return errInjectedRepositoryFailure
}

func (failingSupplyChainRepository) InsertArtifactSignature(context.Context, domain.ArtifactSignature) error {
	return errInjectedRepositoryFailure
}

func (failingSourceRepository) InsertSourceRepository(context.Context, domain.SourceRepository) error {
	return errInjectedRepositoryFailure
}

func (failingSourceRepository) InsertSourceCommit(context.Context, domain.SourceCommit) error {
	return errInjectedRepositoryFailure
}

func TestCollectorCredentialCommitsOnlyAfterUnitOfWorkCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	collector, key, secret, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "build-collector", Type: collectorTypeGenericCI, Version: "1.0.0"})
	if err != nil {
		t.Fatalf("create collector: %v", err)
	}
	if collector.ID == "" || key.ID == "" || key.Hash != "" || secret == "" {
		t.Fatalf("collector result=%#v key=%#v secret=%q", collector, key, secret)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.Collectors[collector.ID].APIKeyID != key.ID || snapshot.APIKeys[key.ID].Hash == "" {
		t.Fatalf("collector credential state is not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Builds = failingBuildRepository{BuildRepository: repositories.Builds}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed collector: %v", err)
	}
	if _, _, failedSecret, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "failed-collector", Type: collectorTypeGenericCI, Version: "1.0.0"}); !errors.Is(err, errInjectedRepositoryFailure) || failedSecret != "" {
		t.Fatalf("failed collector secret=%q err=%v", failedSecret, err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed collector: %v", err)
	}
	if len(after.Collectors) != len(before.Collectors) || len(after.APIKeys) != len(before.APIKeys) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatalf("collector failure published state: before=%#v after=%#v", before, after)
	}
}

func TestCollectorReleaseUsesUnitOfWorkAndPublishesPinnedStateAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	collector, _, _, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "release-collector", Type: collectorTypeGenericCI, Version: "1.0.0"})
	if err != nil {
		t.Fatalf("create collector: %v", err)
	}
	release, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{CollectorID: collector.ID, Version: "1.0.0", ArtifactDigest: sampleDigest("collector-release"), Pinned: true})
	if err != nil {
		t.Fatalf("record collector release: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored, ok := snapshot.CollectorReleases[release.ID]; !ok || !stored.Pinned {
		t.Fatalf("collector release is not committed: %#v", snapshot)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease{ID: "colrel_invalid", TenantID: actor.TenantID, CollectorID: collector.ID, ArtifactDigest: sampleDigest("collector-release-invalid"), VerificationStatus: "recorded", HealthStatus: "needs_evidence", SchemaVersion: domain.CollectorReleaseSchemaVersion, CreatedAt: fixedNow()})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid collector release err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease{ID: "colrel_missing", TenantID: actor.TenantID, CollectorID: "col_missing", Version: "1.0.0", ArtifactDigest: sampleDigest("collector-release-missing"), VerificationStatus: "recorded", HealthStatus: "needs_evidence", SchemaVersion: domain.CollectorReleaseSchemaVersion, CreatedAt: fixedNow()})
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing collector release err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Builds.InsertCollectorRelease(ctx, release)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate collector release err=%v, want conflict", err)
	}
	replacement, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{CollectorID: collector.ID, Version: "1.1.0", ArtifactDigest: sampleDigest("collector-release-replacement"), Pinned: true})
	if err != nil {
		t.Fatalf("replace pinned collector release: %v", err)
	}
	snapshot, err = memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after pin replacement: %v", err)
	}
	if snapshot.CollectorReleases[release.ID].Pinned || !snapshot.CollectorReleases[replacement.ID].Pinned || ledger.collectorReleases[release.ID].Pinned {
		t.Fatalf("pinned collector state did not atomically move: %#v", snapshot.CollectorReleases)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Builds = failingBuildRepository{BuildRepository: repositories.Builds}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed release: %v", err)
	}
	if _, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{CollectorID: collector.ID, Version: "2.0.0", ArtifactDigest: sampleDigest("collector-release-failed"), Pinned: true}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed collector release err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed release: %v", err)
	}
	if len(after.CollectorReleases) != len(before.CollectorReleases) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || !ledger.collectorReleases[replacement.ID].Pinned {
		t.Fatalf("collector release failure published state: before=%#v after=%#v", before, after)
	}
}

func TestBuildRunWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Build API", "build-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("build-uow"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	input := CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}}
	build, err := ledger.CreateBuildRun(ctx, actor, input)
	if err != nil {
		t.Fatalf("create build: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.BuildRuns[build.ID]; !ok {
		t.Fatalf("build is not committed: %#v", snapshot)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		invalid := build
		invalid.ID = "build_invalid_output"
		invalid.Outputs = []domain.BuildOutput{{Digest: ""}}
		return repositories.Builds.InsertBuildRun(ctx, invalid)
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid build output err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingProject := build
		missingProject.ID = "build_missing_project"
		missingProject.ProjectID = "proj_missing"
		return repositories.Builds.InsertBuildRun(ctx, missingProject)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing build project err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		duplicate := build
		return repositories.Builds.InsertBuildRun(ctx, duplicate)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate build err=%v, want conflict", err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Builds = failingBuildRepository{BuildRepository: repositories.Builds}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed write: %v", err)
	}
	if _, err := ledger.CreateBuildRun(ctx, actor, input); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed build write err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed write: %v", err)
	}
	if len(after.BuildRuns) != len(before.BuildRuns) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatalf("build repository failure published state: before=%#v after=%#v", before, after)
	}
}

func TestBuildAttestationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Attestation API", "attestation-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("attestation-uow"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}
	attestation, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest))
	if err != nil {
		t.Fatalf("upload build attestation: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.Evidence[attestation.EvidenceID]; !ok || snapshot.BuildAttestations[attestation.ID].EvidenceID != attestation.EvidenceID || len(snapshot.OutboxJobs) != 1 || len(snapshot.AuditEntries[actor.TenantID]) < 2 {
		t.Fatalf("attestation command did not commit all durable effects: %#v", snapshot)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Builds.InsertBuildAttestation(ctx, domain.BuildAttestation{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid attestation err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingEvidence := attestation
		missingEvidence.ID = "att_missing_evidence"
		missingEvidence.EvidenceID = "ev_missing"
		return repositories.Builds.InsertBuildAttestation(ctx, missingEvidence)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing attestation evidence err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Builds.InsertBuildAttestation(ctx, attestation)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate attestation err=%v, want conflict", err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Builds = failingBuildRepository{BuildRepository: repositories.Builds}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed attestation: %v", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest)); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed attestation err=%v, want injected repository failure", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed attestation: %v", err)
	}
	if len(after.Evidence) != len(before.Evidence) || len(after.BuildAttestations) != len(before.BuildAttestations) || len(after.OutboxJobs) != len(before.OutboxJobs) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.attestations) != 1 {
		t.Fatalf("failed attestation published state: before=%#v after=%#v", before, after)
	}
}

func TestSupplyChainWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("supply-chain-uow"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	image, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api", Digest: artifact.Digest})
	if err != nil {
		t.Fatalf("register image: %v", err)
	}
	signature, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "signature"})
	if err != nil {
		t.Fatalf("create signature: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.ContainerImages[image.ID].ArtifactID != artifact.ID || snapshot.ArtifactSignatures[signature.ID].SubjectDigest != artifact.Digest {
		t.Fatalf("supply-chain writes not committed: %#v", snapshot)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.SupplyChain.InsertContainerImage(ctx, domain.ContainerImage{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid image err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid signature err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingArtifact := image
		missingArtifact.ID = "img_missing_artifact"
		missingArtifact.ArtifactID = "art_missing"
		return repositories.SupplyChain.InsertContainerImage(ctx, missingArtifact)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("image missing artifact err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		mismatchedDigest := image
		mismatchedDigest.ID = "img_mismatched_digest"
		mismatchedDigest.Digest = "sha256:other-image"
		return repositories.SupplyChain.InsertContainerImage(ctx, mismatchedDigest)
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("image mismatched digest err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.SupplyChain.InsertContainerImage(ctx, image)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate image err=%v, want conflict", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingArtifact := signature
		missingArtifact.ID = "artsig_missing_artifact"
		missingArtifact.ArtifactID = "art_missing"
		return repositories.SupplyChain.InsertArtifactSignature(ctx, missingArtifact)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("signature missing artifact err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		mismatchedDigest := signature
		mismatchedDigest.ID = "artsig_mismatched_digest"
		mismatchedDigest.SubjectDigest = "sha256:other-signature"
		return repositories.SupplyChain.InsertArtifactSignature(ctx, mismatchedDigest)
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("signature mismatched digest err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.SupplyChain.InsertArtifactSignature(ctx, signature)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate signature err=%v, want conflict", err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.SupplyChain = failingSupplyChainRepository{SupplyChainRepository: repositories.SupplyChain}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api-failed", Digest: artifact.Digest}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed image err=%v, want injected repository failure", err)
	}
	if _, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "failed-signature"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed signature err=%v, want injected repository failure", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.ContainerImages) != len(before.ContainerImages) || len(after.ArtifactSignatures) != len(before.ArtifactSignatures) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.images) != 1 || len(ledger.artifactSigs) != 1 {
		t.Fatalf("failed supply-chain write published state: before=%#v after=%#v", before, after)
	}
}

func TestSourceWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Source API", "source-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	repository, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "example/api"})
	if err != nil {
		t.Fatalf("create source repository: %v", err)
	}
	commit, err := ledger.RecordSourceCommit(ctx, actor, RecordCommitInput{RepositoryID: repository.ID, SHA: "0123456789abcdef0123456789abcdef01234567", CommittedAt: fixedNow()})
	if err != nil {
		t.Fatalf("record source commit: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.SourceRepositories[repository.ID].ProjectID != project.ID || snapshot.SourceCommits[commit.ID].RepositoryID != repository.ID {
		t.Fatalf("source writes not committed: %#v", snapshot)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Source.InsertSourceRepository(ctx, domain.SourceRepository{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid source repository err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingProject := repository
		missingProject.ID = "repo_missing_project"
		missingProject.FullName = "example/missing-project"
		missingProject.ProjectID = "proj_missing"
		return repositories.Source.InsertSourceRepository(ctx, missingProject)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("source repository missing project err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Source.InsertSourceRepository(ctx, repository)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate source repository err=%v, want conflict", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		missingRepository := commit
		missingRepository.ID = "commit_missing_repository"
		missingRepository.RepositoryID = "repo_missing"
		return repositories.Source.InsertSourceCommit(ctx, missingRepository)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("source commit missing repository err=%v, want not found", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Source.InsertSourceCommit(ctx, commit)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate source commit err=%v, want conflict", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Source = failingSourceRepository{SourceRepository: repositories.Source}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "example/failing"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed source repository err=%v", err)
	}
	if _, err := ledger.RecordSourceCommit(ctx, actor, RecordCommitInput{RepositoryID: repository.ID, SHA: "1123456789abcdef0123456789abcdef01234567", CommittedAt: fixedNow()}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed source commit err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.SourceRepositories) != len(before.SourceRepositories) || len(after.SourceCommits) != len(before.SourceCommits) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.repositories) != 1 || len(ledger.commits) != 1 {
		t.Fatalf("failed source write published state: before=%#v after=%#v", before, after)
	}
}
