package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func newNativeReleaseAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeAuthorizationFixture(t)
	for _, scope := range []operationsFixtureScope{f.owner, f.foreign} {
		project := f.project
		if scope.actor.TenantID != f.owner.actor.TenantID {
			var err error
			project, err = releaseSetup(f.ledger).CreateProject(t.Context(), scope.actor, scope.product.ID, "Foreign project")
			if err != nil {
				t.Fatal(err)
			}
		}
		artifact := seedArtifactNativeFixture(t, f.ledger, scope)
		build, err := releaseSetup(f.ledger).CreateBuildRun(t.Context(), scope.actor, releaseapp.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: scope.release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: scope.release.CreatedAt, Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := releaseSetup(f.ledger).CreateReleaseCandidate(t.Context(), scope.actor, releaseapp.CreateReleaseCandidateInput{ReleaseID: scope.release.ID, Name: "Candidate", BuildIDs: []string{build.ID}, ArtifactIDs: []string{artifact.ID}})
		if err != nil {
			t.Fatal(err)
		}
		commands := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: f.ledger}}
		environment, err := commands.CreateDeploymentEnvironment(t.Context(), scope.actor, operationsapp.CreateEnvironmentInput{ProductID: scope.product.ID, Name: "Production", Kind: "production"})
		if err != nil {
			t.Fatal(err)
		}
		deployment, err := commands.RecordDeployment(t.Context(), scope.actor, operationsapp.RecordDeploymentInput{EnvironmentID: environment.ID, ReleaseID: scope.release.ID, Status: "succeeded", StartedAt: scope.release.CreatedAt, ArtifactIDs: []string{artifact.ID}})
		if err != nil {
			t.Fatal(err)
		}
		if scope.actor.TenantID == f.owner.actor.TenantID {
			f.artifact, f.build, f.candidate = artifact, build, candidate
			f.environment, f.deployment = domain.DeploymentEnvironment(environment), domain.DeploymentEvent(deployment)
		}
	}
	return f
}

func addNativeReleaseDeploymentAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation, path string
		foreign         int
		id              func(nativeAuthorizationFixture) string
	}{
		{"getArtifact", "/v1/artifacts/", 404, func(f nativeAuthorizationFixture) string { return f.artifact.ID }},
		{"getBuild", "/v1/builds/", 404, func(f nativeAuthorizationFixture) string { return f.build.ID }},
		{"getReleaseCandidate", "/v1/release-candidates/", 404, func(f nativeAuthorizationFixture) string { return f.candidate.ID }},
		{"getDeployment", "/v1/deployments/", 404, func(f nativeAuthorizationFixture) string { return f.deployment.ID }},
		{"listReleaseCandidates", "/v1/release-candidates", 200, func(f nativeAuthorizationFixture) string { return f.candidate.ID }},
		{"listDeploymentEnvironments", "/v1/environments", 200, func(f nativeAuthorizationFixture) string { return f.environment.ID }},
		{"listDeployments", "/v1/deployments", 200, func(f nativeAuthorizationFixture) string { return f.deployment.ID }},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeReleaseAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			if tc.foreign == 404 {
				return tc.path + tc.id(f)
			}
			return tc.path
		}, tc.id, tc.foreign)
	}
	cases["startReleaseEvidenceFlow"] = nativeReadAuthorizationFixtureMethodCase("startReleaseEvidenceFlow", http.MethodPost, newNativeReleaseAuthorizationFixture, func(f nativeAuthorizationFixture) string {
		return "/v1/releases/" + f.owner.release.ID + "/evidence-flow/start"
	}, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404)
	for _, tc := range []struct {
		operation, path string
		foreign         int
		body            func(nativeAuthorizationFixture) string
	}{
		{"registerArtifact", "/v1/artifacts", 0, func(nativeAuthorizationFixture) string {
			return `{"name":"New artifact","media_type":"application/octet-stream","digest":"sha256:` + strings.Repeat("c", 64) + `","size":42}`
		}},
		{"registerContainerImage", "/v1/container-images", 404, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"artifact_id":%q,"repository":"example/api","tag":"1","digest":%q,"platform":"linux/amd64"}`, f.artifact.ID, f.artifact.Digest)
		}},
		{"createBuild", "/v1/builds", 404, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"project_id":%q,"release_id":%q,"provider":"generic_ci","commit_sha":%q,"status":"passed","started_at":"2026-10-07T16:00:00Z"}`, f.project.ID, f.owner.release.ID, strings.Repeat("b", 40))
		}},
		{"createReleaseCandidate", "/v1/release-candidates", 404, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"release_id":%q,"name":"New candidate","build_ids":[%q],"artifact_ids":[%q]}`, f.owner.release.ID, f.build.ID, f.artifact.ID)
		}},
		{"createDeploymentEnvironment", "/v1/environments", 404, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"product_id":%q,"name":"Staging","kind":"staging"}`, f.owner.product.ID)
		}},
		{"recordDeployment", "/v1/deployments", 404, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"environment_id":%q,"release_id":%q,"status":"succeeded","started_at":"2026-10-07T16:00:00Z","artifact_ids":[%q]}`, f.environment.ID, f.owner.release.ID, f.artifact.ID)
		}},
	} {
		expected := nativeMutationExpectation{status: 201, foreignStatus: tc.foreign, auditDelta: 1}
		if tc.operation == "recordDeployment" {
			expected.auditDelta = 2
		} // evidence.created plus deployment.recorded
		if tc.operation == "registerArtifact" {
			// New digest registration is capability-only: it cannot consult a
			// nonexistent association. Current grants protect deduplication of
			// an already registered artifact, including its metadata/replay.
			expected.revokedInput = func(f nativeAuthorizationFixture) (string, []byte) {
				return tc.path, []byte(fmt.Sprintf(`{"name":"Existing artifact","media_type":"application/octet-stream","digest":%q,"size":42}`, f.artifact.Digest))
			}
		}
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeReleaseAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) { return tc.path, []byte(tc.body(f)) }, expected)
	}
	for _, tc := range []struct {
		operation, suffix string
		candidate         bool
	}{
		{"freezeRelease", "freeze", false}, {"approveRelease", "approve", false}, {"promoteReleaseCandidate", "promote", true}, {"rejectReleaseCandidate", "reject", true},
	} {
		fixture := func(t *testing.T) nativeAuthorizationFixture {
			f := newNativeReleaseAuthorizationFixture(t)
			if tc.operation == "approveRelease" {
				_, err := (lifecycleFixtureCommands{catalogFixtureCommands{ledger: f.ledger}}).FreezeRelease(t.Context(), f.owner.actor, f.owner.release.ID, 1)
				if err != nil {
					t.Fatal(err)
				}
			}
			return f
		}
		revision := `"1"`
		if tc.operation == "approveRelease" {
			revision = `"2"`
		}
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, fixture, func(f nativeAuthorizationFixture) (string, []byte) {
			if tc.candidate {
				return "/v1/release-candidates/" + f.candidate.ID + "/" + tc.suffix, []byte(`{"reason":"Reviewed"}`)
			}
			return "/v1/releases/" + f.owner.release.ID + "/" + tc.suffix, []byte(`{}`)
		}, nativeMutationExpectation{status: 200, foreignStatus: 404, auditDelta: 1, headers: map[string]string{"If-Match": revision}})
	}
}
