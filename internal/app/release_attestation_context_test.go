package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestBuildAttestationAuditsUseHumanCollectorAndAPIKeyIdentity(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, apiActor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, apiActor, "Attestation audit", "attestation-audit")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, apiActor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, apiActor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, apiActor, "api.tar.gz", "application/gzip", sampleDigest("attestation-audit"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, apiActor, CreateBuildRunInput{
		ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(),
		Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}
	_, _, collectorSecret, err := ledger.CreateCollector(ctx, apiActor, CreateCollectorInput{Name: "audit-collector", Type: collectorTypeGenericCI, Version: "1.0.0"})
	if err != nil {
		t.Fatalf("create collector: %v", err)
	}
	collectorActor, err := ledger.Authenticate(ctx, collectorSecret)
	if err != nil {
		t.Fatalf("authenticate collector: %v", err)
	}
	humanActor := domain.Actor{
		TenantID: apiActor.TenantID, UserID: "usr_audit", SessionID: "sess_audit", Scopes: []string{"*"},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: apiActor.TenantID, Scopes: []string{"*"}}},
	}

	tests := []struct {
		name      string
		actor     domain.Actor
		actorType string
		actorID   string
	}{
		{name: "api key", actor: apiActor, actorType: "api_key", actorID: apiActor.KeyID},
		{name: "human", actor: humanActor, actorType: "human_user", actorID: humanActor.UserID},
		{name: "collector", actor: collectorActor, actorType: "collector", actorID: collectorActor.CollectorID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attestation, err := ledger.UploadBuildAttestation(ctx, test.actor, build.ID, dsseForDigest(t, artifact.Digest))
			if err != nil {
				t.Fatalf("upload attestation: %v", err)
			}
			snapshot, err := memory.Snapshot()
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			assertAttestationAuditActor(t, snapshot.AuditEntries[apiActor.TenantID], "evidence_item", attestation.EvidenceID, test.actorType, test.actorID)
			assertAttestationAuditActor(t, snapshot.AuditEntries[apiActor.TenantID], "build_attestation", attestation.ID, test.actorType, test.actorID)
		})
	}
}

func TestBuildAttestationUsesDocumentedBuildWriteForAPIKeyAndHumanActors(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, bootstrapActor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, bootstrapActor, "Attestation scope", "attestation-scope")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, bootstrapActor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, bootstrapActor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, bootstrapActor, "api.tar.gz", "application/gzip", sampleDigest("attestation-scope"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, bootstrapActor, CreateBuildRunInput{
		ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(),
		Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}

	actors := []struct {
		name  string
		actor domain.Actor
	}{
		{
			name:  "api key",
			actor: domain.Actor{TenantID: bootstrapActor.TenantID, KeyID: "key_build_only", Scopes: []string{ScopeBuildWrite}},
		},
		{
			name: "human",
			actor: domain.Actor{
				TenantID: bootstrapActor.TenantID, UserID: "usr_build_only", SessionID: "sess_build_only", Scopes: []string{ScopeBuildWrite},
				ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{ScopeBuildWrite}}},
			},
		},
	}
	for _, test := range actors {
		t.Run(test.name, func(t *testing.T) {
			if test.actor.HasScope(ScopeEvidenceWrite) {
				t.Fatal("test actor unexpectedly has evidence:write")
			}
			attestation, err := ledger.UploadBuildAttestation(ctx, test.actor, build.ID, dsseForDigest(t, artifact.Digest))
			if err != nil {
				t.Fatalf("upload with build:write: %v", err)
			}
			if attestation.EvidenceID == "" {
				t.Fatalf("attestation missing evidence: %#v", attestation)
			}
		})
	}

	denied := domain.Actor{
		TenantID: bootstrapActor.TenantID, UserID: "usr_wrong_project", SessionID: "sess_wrong_project", Scopes: []string{ScopeBuildWrite},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: "proj_other", Scopes: []string{ScopeBuildWrite}}},
	}
	if _, err := ledger.UploadBuildAttestation(ctx, denied, build.ID, []byte(`not-json`)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied malformed payload error = %v, want authorization before parse", err)
	}
}

func assertAttestationAuditActor(t *testing.T, entries []domain.AuditChainEntry, subjectType, subjectID, wantType, wantID string) {
	t.Helper()
	for _, entry := range entries {
		if entry.SubjectType == subjectType && entry.SubjectID == subjectID {
			if entry.ActorType != wantType || entry.ActorID != wantID {
				t.Fatalf("audit actor = (%q, %q), want (%q, %q): %#v", entry.ActorType, entry.ActorID, wantType, wantID, entry)
			}
			return
		}
	}
	t.Fatalf("missing audit for %s %s", subjectType, subjectID)
}
