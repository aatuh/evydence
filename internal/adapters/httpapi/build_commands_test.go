package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildCreationHTTPFake struct {
	calls int
	actor identitydomain.Actor
	input releaseapp.CreateBuildRunInput
	err   error
}

func (f *buildCreationHTTPFake) CreateBuildRun(_ context.Context, a identitydomain.Actor, in releaseapp.CreateBuildRunInput) (releasedomain.BuildRun, error) {
	f.calls++
	f.actor = a
	f.input = in
	return releasedomain.BuildRun{ID: "durable-build", TenantID: a.TenantID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Outputs: in.Outputs}, f.err
}
func TestBuildCreationHTTPMapsDTOAndSafeReplayWithoutLedgerParents(t *testing.T) {
	local, secret := testServer(t)
	fake := &buildCreationHTTPFake{}
	server, err := NewServerWithOptions(local.ledger, ServerOptions{BuildCommands: fake})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"project_id":"project","release_id":"release","provider":"generic_ci","commit_sha":"commit","repository":"example/repository","workflow_ref":"build.yml","run_id":"42","run_attempt":2,"job_id":"job","actor":"builder","ref":"main","oidc_subject":"subject","status":"passed","started_at":"2026-10-02T12:00:00Z","finished_at":"2026-10-02T12:01:00Z","parameters_hash":"sha256:parameters","environment_hash":"sha256:environment","provider_metadata":{"custom":{"ok":true}},"outputs":[{"artifact_id":"artifact","digest":"sha256:output"}]}`)
	response := postRaw(t, server, secret, "/v1/builds", "create-build", body, 201)
	finished := time.Date(2026, 10, 2, 12, 1, 0, 0, time.UTC)
	want := releaseapp.CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: "commit", Repository: "example/repository", WorkflowRef: "build.yml", RunID: "42", RunAttempt: 2, JobID: "job", GitHubActor: "builder", Ref: "main", OIDCSubject: "subject", Status: "passed", StartedAt: finished.Add(-time.Minute), FinishedAt: &finished, ParametersHash: "sha256:parameters", EnvironmentHash: "sha256:environment", ProviderMetadata: map[string]any{"custom": map[string]any{"ok": true}}, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:output"}}}
	if fake.calls != 1 || fake.actor.TenantID == "" || !reflect.DeepEqual(fake.input, want) || !strings.Contains(response, `"id":"durable-build"`) {
		t.Fatal("DTO mismatch", fake, response)
	}
	if replay := postRaw(t, server, secret, "/v1/builds", "create-build", body, 201); replay != response || fake.calls != 1 {
		t.Fatal("replay repeated command", fake, replay)
	}
	postRaw(t, server, secret, "/v1/builds", "create-build", append(body, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private SQL secret"), 500}} {
		fake.err = tc.err
		failure := postRaw(t, server, secret, "/v1/builds", fmt.Sprintf("failed-build-%d", i), body, tc.status)
		if strings.Contains(failure, "private SQL") || strings.Contains(failure, "durable-build") {
			t.Fatal("error leaked result or backend detail", failure)
		}
	}
	fake.err = nil
	empty := postRaw(t, server, secret, "/v1/builds", "empty-outputs", []byte(`{"project_id":"project"}`), 201)
	if strings.Contains(empty, `"outputs"`) {
		t.Fatal("empty output omission contract changed", empty)
	}
}
