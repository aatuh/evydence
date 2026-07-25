package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingBuildRepository struct{ BuildRepository }

func (failingBuildRepository) InsertBuildRun(context.Context, domain.BuildRun) error {
	return errInjectedRepositoryFailure
}

func (failingBuildRepository) InsertCollector(context.Context, domain.Collector) error {
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
