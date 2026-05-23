package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestEvidenceSearchAndLifecycleEventsAreTenantScopedAppendOnly(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actorA, releaseA, _ := setupReleaseRiskFixture(t, ledger)
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}

	item, err := ledger.CreateEvidence(ctx, actorA, CreateEvidenceInput{
		ReleaseID:    releaseA.ID,
		Type:         "build",
		Subtype:      "log",
		Title:        "Build log",
		SourceSystem: "github_actions",
		PayloadHash:  sampleDigest("build-log"),
		Tags:         []string{"ci", "release"},
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	results, err := ledger.SearchEvidence(ctx, actorA, EvidenceSearchInput{ReleaseID: releaseA.ID, Type: "build", Tag: "ci"})
	if err != nil {
		t.Fatalf("search evidence: %v", err)
	}
	if len(results) != 1 || results[0].ID != item.ID {
		t.Fatalf("search results = %#v, want created evidence", results)
	}
	if results, err := ledger.SearchEvidence(ctx, actorB, EvidenceSearchInput{ReleaseID: releaseA.ID}); err != nil || len(results) != 0 {
		t.Fatalf("cross-tenant search results=%#v err=%v, want empty nil", results, err)
	}
	event, err := ledger.RecordEvidenceLifecycleEvent(ctx, actorA, item.ID, RecordEvidenceLifecycleInput{Action: lifecycleRedaction, Reason: "customer-visible package redaction"})
	if err != nil {
		t.Fatalf("record lifecycle: %v", err)
	}
	after, err := ledger.GetEvidence(ctx, actorA, item.ID)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	if after.PayloadHash != item.PayloadHash || after.CanonicalHash != item.CanonicalHash {
		t.Fatal("lifecycle event mutated immutable evidence fields")
	}
	events, err := ledger.ListEvidenceLifecycleEvents(ctx, actorA, item.ID)
	if err != nil {
		t.Fatalf("list lifecycle: %v", err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %#v, want recorded event", events)
	}
	if _, err := ledger.ListEvidenceLifecycleEvents(ctx, actorB, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lifecycle list err=%v, want not found", err)
	}
}

func TestReleaseCandidateContainerImageAndArtifactSignature(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	candidate, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{
		ReleaseID:   release.ID,
		Name:        "rc.1",
		ArtifactIDs: []string{artifact.ID},
	})
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	if candidate.SnapshotHash == "" || candidate.State != candidateOpen {
		t.Fatalf("candidate = %#v, want open with snapshot hash", candidate)
	}
	promoted, err := ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidatePromoted, "release accepted")
	if err != nil {
		t.Fatalf("promote candidate: %v", err)
	}
	if promoted.PromotedAt == nil || promoted.State != candidatePromoted {
		t.Fatalf("promoted = %#v, want promoted timestamp", promoted)
	}
	if _, err := ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidateRejected, "late rejection"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second candidate transition err=%v, want conflict", err)
	}
	image, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{
		ArtifactID: artifact.ID,
		Repository: "ghcr.io/example/payments",
		Tag:        "1.0.0",
		Digest:     artifact.Digest,
		Platform:   "linux/amd64",
	})
	if err != nil {
		t.Fatalf("image: %v", err)
	}
	if image.ArtifactID != artifact.ID {
		t.Fatalf("image artifact id = %s, want %s", image.ArtifactID, artifact.ID)
	}
	sig, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{
		ArtifactID: artifact.ID,
		Algorithm:  "cosign",
		KeyID:      "test-key",
		Signature:  "base64-signature-placeholder",
		RawPayload: []byte(`{"signature":"base64-signature-placeholder"}`),
	})
	if err != nil {
		t.Fatalf("artifact signature: %v", err)
	}
	vr, err := ledger.VerifySubject(ctx, actor, "artifact_signature", sig.ID)
	if err != nil {
		t.Fatalf("verify artifact signature: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("artifact signature verification = %s, want passed", vr.Result)
	}
}

func TestSourceCollectorsAndBuildProviders(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	collector, _, secret, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "gitlab", Type: collectorTypeGitLabCI, Version: "0.1.0", Scopes: []string{ScopeBuildWrite, ScopeSourceWrite, ScopeEvidenceWrite}})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	collectorActor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("collector auth: %v", err)
	}
	if collectorActor.CollectorID != collector.ID {
		t.Fatalf("collector actor id = %s, want %s", collectorActor.CollectorID, collector.ID)
	}
	build, err := ledger.CreateBuildRun(ctx, collectorActor, CreateBuildRunInput{
		ProjectID:  project.ID,
		ReleaseID:  release.ID,
		Provider:   collectorTypeGitLabCI,
		CommitSHA:  "0123456789abcdef0123456789abcdef01234567",
		Repository: "group/project",
		RunID:      "12345",
		Status:     buildStatusPassed,
		StartedAt:  fixedNow(),
		Outputs:    []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("gitlab build: %v", err)
	}
	if build.CollectorID != collector.ID || build.SourceIdentity["provider"] != collectorTypeGitLabCI {
		t.Fatalf("build source identity = %#v", build.SourceIdentity)
	}
	snapshot := `{
		"project_id":"` + project.ID + `",
		"repository":{"full_name":"group/project","clone_url":"https://gitlab.example/group/project.git","default_branch":"main"},
		"commit":{"sha":"0123456789abcdef0123456789abcdef01234567","author":"dev@example.test","message":"change","committed_at":"2026-05-28T10:00:00Z"},
		"branch":{"name":"main","protected":true,"protection_hash":"` + sampleDigest("protection") + `"},
		"pull_request":{"provider_id":"17","title":"Change","state":"merged","source_branch":"feature","target_branch":"main","review_decision":"approved"}
	}`
	result, err := ledger.UploadGitLabSourceSnapshot(ctx, collectorActor, []byte(snapshot))
	if err != nil {
		t.Fatalf("source snapshot: %v", err)
	}
	if result["repository"] == nil || result["commit"] == nil || result["pull_request"] == nil {
		t.Fatalf("snapshot result missing resources: %#v", result)
	}
}

func TestDeploymentEvidenceIsTenantScopedAndAppendOnly(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	env, err := ledger.CreateDeploymentEnvironment(ctx, actor, CreateEnvironmentInput{ProductID: release.ProductID, Name: "production", Kind: "production"})
	if err != nil {
		t.Fatalf("environment: %v", err)
	}
	deployment, err := ledger.RecordDeployment(ctx, actor, RecordDeploymentInput{
		EnvironmentID: env.ID,
		ReleaseID:     release.ID,
		ArtifactIDs:   []string{artifact.ID},
		Status:        deploymentStatusSucceeded,
		StartedAt:     time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("deployment: %v", err)
	}
	item, err := ledger.GetEvidence(ctx, actor, deployment.EvidenceID)
	if err != nil {
		t.Fatalf("deployment evidence: %v", err)
	}
	if item.Type != "deployment" || item.DeploymentID != deployment.ID {
		t.Fatalf("deployment evidence = %#v", item)
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	if _, err := ledger.RecordDeployment(ctx, actorB, RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: release.ID, Status: deploymentStatusSucceeded}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant deployment err=%v, want not found", err)
	}
}
