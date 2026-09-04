package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestCreateBuildRunPreservesLegacyInputAndCommitsAtomically(t *testing.T) {
	fixture := newServiceFixture(t)
	product, project, release := seedReleaseScope(t, fixture)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: digest}
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	fixture.actor.CollectorID = "col_1"
	clockCalls := 0
	fixture.service.clock = application.ClockFunc(func() time.Time {
		clockCalls++
		return fixture.now
	})

	finishedAt := fixture.now.Add(-time.Minute)
	build, err := fixture.service.CreateBuildRun(context.Background(), fixture.actor, CreateBuildRunInput{
		ProjectID: " " + project.ID + " ", ReleaseID: " " + release.ID + " ", Provider: " generic_ci ",
		CommitSHA: strings.Repeat("a", 40), Repository: " example/repository ", WorkflowRef: " build.yml@main ",
		RunID: " 42 ", RunAttempt: 2, JobID: " job-1 ", GitHubActor: " builder ", Ref: " refs/heads/main ",
		OIDCSubject: " subject ", Status: " passed ", StartedAt: fixture.now.Add(-2 * time.Minute), FinishedAt: &finishedAt,
		ParametersHash: testSHA256('b'), EnvironmentHash: testSHA256('c'),
		ProviderMetadata: map[string]any{"source": "untrusted", "custom": "retained"},
		Outputs:          []releasedomain.BuildOutput{{ArtifactID: " " + artifact.ID + " ", Digest: " " + digest + " "}},
	})
	if err != nil {
		t.Fatalf("CreateBuildRun: %v", err)
	}
	if clockCalls != 1 || fixture.transactions.calls != 1 || fixture.transactions.commits != 1 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("clock=%d transactions=%#v", clockCalls, fixture.transactions)
	}
	if build.ID != "build_1" || build.TenantID != fixture.actor.TenantID || build.ProjectID != project.ID || build.ReleaseID != release.ID || build.CollectorID != fixture.actor.CollectorID {
		t.Fatalf("build identity = %#v", build)
	}
	if build.Provider != "generic_ci" || build.Status != "passed" || build.Outputs[0].ArtifactID != artifact.ID || build.Outputs[0].Digest != digest {
		t.Fatalf("normalized build = %#v", build)
	}
	if build.SchemaVersion != releasedomain.BuildRunSchemaVersion || !build.CreatedAt.Equal(fixture.now) {
		t.Fatalf("build version/time = %#v", build)
	}
	if build.SourceIdentity["source"] != "collector" || build.SourceIdentity["collector_id"] != fixture.actor.CollectorID || build.SourceIdentity["custom"] != "retained" {
		t.Fatalf("source identity = %#v", build.SourceIdentity)
	}
	if len(fixture.authorizer.requests) != 3 {
		t.Fatalf("authorization requests = %#v", fixture.authorizer.requests)
	}
	wantResources := application.ResourceReferences{ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID}
	if request := fixture.authorizer.requests[1]; request.Scope != ScopeBuildWrite || request.Resources != wantResources || request.ScopeOnly {
		t.Fatalf("resource authorization = %#v", request)
	}
	wantArtifactResources := application.ResourceReferences{ArtifactID: artifact.ID}
	if request := fixture.authorizer.requests[2]; request.Scope != ScopeBuildWrite || request.Resources != wantArtifactResources || request.ScopeOnly {
		t.Fatalf("artifact authorization = %#v", request)
	}
	stored, ok := fixture.transactions.state.builds[build.ID]
	if !ok || !reflect.DeepEqual(stored, build) {
		t.Fatalf("stored build = %#v, ok=%t", stored, ok)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	event := fixture.transactions.state.audit[0]
	if event.EntryType != "build.created" || event.SubjectType != "build_run" || event.SubjectID != build.ID || event.ActorType != "collector" || event.ActorID != fixture.actor.CollectorID || !event.OccurredAt.Equal(build.CreatedAt) {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestCreateBuildRunRejectsWrongTenantOutputBeforeTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	_, project, release := seedReleaseScope(t, fixture)
	digest := testSHA256('a')
	fixture.reader.artifacts["art_other"] = releasedomain.Artifact{ID: "art_other", TenantID: "ten_other", Digest: digest}

	_, err := fixture.service.CreateBuildRun(context.Background(), fixture.actor, CreateBuildRunInput{
		ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40),
		Status: "passed", StartedAt: fixture.now, Outputs: []releasedomain.BuildOutput{{ArtifactID: "art_other", Digest: digest}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateBuildRun error = %v, want not found", err)
	}
	if fixture.transactions.calls != 0 {
		t.Fatalf("transactions = %d, want 0", fixture.transactions.calls)
	}
}

func TestCreateBuildRunRequiresArtifactOnlyAuthorizationBeforeTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	_, project, release := seedReleaseScope(t, fixture)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: digest}
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: artifact.ID}) {
			return errDenied
		}
		return nil
	}

	_, err := fixture.service.CreateBuildRun(context.Background(), fixture.actor, CreateBuildRunInput{
		ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40),
		Status: "passed", StartedAt: fixture.now, Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}},
	})
	if !errors.Is(err, errDenied) {
		t.Fatalf("CreateBuildRun error = %v, want denied", err)
	}
	if fixture.transactions.calls != 0 || len(fixture.transactions.state.builds) != 0 {
		t.Fatalf("denied command touched transactions=%d builds=%#v", fixture.transactions.calls, fixture.transactions.state.builds)
	}
}

func TestCreateBuildRunPreservesLegacyProviderValidation(t *testing.T) {
	valid := CreateBuildRunInput{
		ProjectID: "proj_1", ReleaseID: "rel_1", Provider: "generic_ci", CommitSHA: strings.Repeat("A", 40),
		Status: buildStatusPassed, StartedAt: time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC),
	}
	for _, test := range []struct {
		name   string
		mutate func(*CreateBuildRunInput)
	}{
		{name: "missing project", mutate: func(input *CreateBuildRunInput) { input.ProjectID = "" }},
		{name: "invalid commit", mutate: func(input *CreateBuildRunInput) { input.CommitSHA = strings.Repeat("z", 40) }},
		{name: "invalid status", mutate: func(input *CreateBuildRunInput) { input.Status = "unknown" }},
		{name: "zero start", mutate: func(input *CreateBuildRunInput) { input.StartedAt = time.Time{} }},
		{name: "invalid parameters hash", mutate: func(input *CreateBuildRunInput) { input.ParametersHash = "sha256:short" }},
		{name: "github repository required", mutate: func(input *CreateBuildRunInput) { input.Provider = buildProviderGitHubActions }},
		{name: "gitlab run required", mutate: func(input *CreateBuildRunInput) { input.Provider = buildProviderGitLabCI; input.Repository = "repo" }},
		{name: "invalid output digest", mutate: func(input *CreateBuildRunInput) {
			input.Outputs = []releasedomain.BuildOutput{{Digest: "sha256:short"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if _, err := normalizeBuildInput(input); !errors.Is(err, ErrValidation) {
				t.Fatalf("normalizeBuildInput error = %v", err)
			}
		})
	}
	build, err := normalizeBuildInput(valid)
	if err != nil || build.CommitSHA != valid.CommitSHA {
		t.Fatalf("uppercase legacy commit digest was not preserved: build=%#v err=%v", build, err)
	}
}

func TestCreateBuildRunRollsBackOnScopeDriftAndAuditFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*serviceFixture)
		wantErr   error
	}{
		{
			name: "transaction wrong tenant",
			configure: func(fixture *serviceFixture) {
				project := fixture.transactions.state.projects["proj_1"]
				project.TenantID = "ten_other"
				fixture.transactions.state.projects[project.ID] = project
			},
			wantErr: ErrNotFound,
		},
		{
			name: "project scope drift",
			configure: func(fixture *serviceFixture) {
				project := fixture.transactions.state.projects["proj_1"]
				project.ProductID = "prod_other"
				fixture.transactions.state.projects[project.ID] = project
			},
			wantErr: ErrConflict,
		},
		{name: "audit failure", configure: func(fixture *serviceFixture) { fixture.transactions.auditErr = errAudit }, wantErr: errAudit},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			_, project, release := seedReleaseScope(t, fixture)
			test.configure(fixture)
			_, err := fixture.service.CreateBuildRun(context.Background(), fixture.actor, CreateBuildRunInput{
				ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40),
				Status: "passed", StartedAt: fixture.now,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("CreateBuildRun error = %v, want %v", err, test.wantErr)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.builds) != 0 {
				t.Fatalf("transactions = %#v builds=%#v", fixture.transactions, fixture.transactions.state.builds)
			}
		})
	}
}

func TestGetBuildRunUsesTenantScopedStableAuthorizationCoordinates(t *testing.T) {
	fixture := newServiceFixture(t)
	product, project, release := seedReleaseScope(t, fixture)
	build := releasedomain.BuildRun{ID: "build_1", TenantID: fixture.actor.TenantID, ProjectID: project.ID, ReleaseID: release.ID}
	fixture.reader.builds[build.ID] = build

	got, err := fixture.service.GetBuildRun(context.Background(), fixture.actor, build.ID)
	if err != nil || !reflect.DeepEqual(got, build) {
		t.Fatalf("GetBuildRun = (%#v, %v)", got, err)
	}
	want := application.ResourceReferences{ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, BuildID: build.ID}
	if len(fixture.authorizer.requests) != 2 || fixture.authorizer.requests[1].Scope != ScopeBuildRead || fixture.authorizer.requests[1].Resources != want {
		t.Fatalf("authorization = %#v", fixture.authorizer.requests)
	}

	fixture = newServiceFixture(t)
	fixture.reader.builds[build.ID] = releasedomain.BuildRun{ID: build.ID, TenantID: "ten_other", ProjectID: project.ID, ReleaseID: release.ID}
	if _, err := fixture.service.GetBuildRun(context.Background(), fixture.actor, build.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-tenant GetBuildRun error = %v", err)
	}
}

func TestCreateReleaseCandidateValidatesReferencesAndHashesCanonicalSnapshot(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	build := releasedomain.BuildRun{ID: "build_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID}
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: testSHA256('a')}
	fixture.transactions.state.builds[build.ID] = build
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	clockCalls := 0
	fixture.service.clock = application.ClockFunc(func() time.Time {
		clockCalls++
		return fixture.now
	})

	candidate, err := fixture.service.CreateReleaseCandidate(context.Background(), fixture.actor, CreateReleaseCandidateInput{
		ReleaseID: " " + release.ID + " ", Name: " Candidate 1 ", BuildIDs: []string{" build_2 ", " build_1 "},
		ArtifactIDs: []string{" art_2 ", " art_1 "}, SBOMIDs: []string{" sbom_1 "}, ScanIDs: []string{" scan_1 "},
		VEXIDs: []string{" vex_1 "}, ContractIDs: []string{" contract_1 "}, BundleIDs: []string{" bundle_1 "},
	})
	if err == nil {
		t.Fatal("CreateReleaseCandidate unexpectedly accepted missing same-context references")
	}
	if !errors.Is(err, ErrNotFound) || fixture.transactions.rollbacks != 1 {
		t.Fatalf("missing-reference error=%v transactions=%#v", err, fixture.transactions)
	}

	fixture = newServiceFixture(t)
	_, _, release = seedReleaseScope(t, fixture)
	for _, id := range []string{"build_1", "build_2"} {
		fixture.transactions.state.builds[id] = releasedomain.BuildRun{ID: id, TenantID: fixture.actor.TenantID, ReleaseID: release.ID}
	}
	for _, id := range []string{"art_1", "art_2"} {
		fixture.transactions.state.artifacts[id] = releasedomain.Artifact{ID: id, TenantID: fixture.actor.TenantID, Digest: testSHA256('a')}
	}
	clockCalls = 0
	fixture.service.clock = application.ClockFunc(func() time.Time { clockCalls++; return fixture.now })
	candidate, err = fixture.service.CreateReleaseCandidate(context.Background(), fixture.actor, CreateReleaseCandidateInput{
		ReleaseID: " " + release.ID + " ", Name: " Candidate 1 ", BuildIDs: []string{" build_2 ", " build_1 "},
		ArtifactIDs: []string{" art_2 ", " art_1 "}, SBOMIDs: []string{" sbom_1 "}, ScanIDs: []string{" scan_1 "},
		VEXIDs: []string{" vex_1 "}, ContractIDs: []string{" contract_1 "}, BundleIDs: []string{" bundle_1 "},
	})
	if err != nil {
		t.Fatalf("CreateReleaseCandidate: %v", err)
	}
	if clockCalls != 1 || candidate.ID != "rc_1" || candidate.Name != "Candidate 1" || candidate.Revision != 1 || candidate.State.String() != releasedomain.ReleaseCandidateStateOpenValue {
		t.Fatalf("candidate = %#v clock=%d", candidate, clockCalls)
	}
	if !reflect.DeepEqual(candidate.BuildIDs, []string{"build_1", "build_2"}) || !reflect.DeepEqual(candidate.ArtifactIDs, []string{"art_1", "art_2"}) {
		t.Fatalf("sorted references = builds %#v artifacts %#v", candidate.BuildIDs, candidate.ArtifactIDs)
	}
	if fixture.references.calls != 1 || fixture.references.tenantID != fixture.actor.TenantID || fixture.references.releaseID != release.ID || !reflect.DeepEqual(fixture.references.references.BuildIDs, candidate.BuildIDs) {
		t.Fatalf("reference validation = %#v", fixture.references)
	}
	if fixture.canonicalizer.calls != 1 || fixture.canonicalizer.candidate.SnapshotHash != "" || candidate.SnapshotHash != fixture.canonicalizer.hash {
		t.Fatalf("canonicalization candidate=%#v result=%#v", fixture.canonicalizer.candidate, candidate)
	}
	if event := fixture.transactions.state.audit[0]; event.PayloadHash != candidate.SnapshotHash || !event.OccurredAt.Equal(candidate.CreatedAt) {
		t.Fatalf("audit = %#v candidate=%#v", event, candidate)
	}
}

func TestCreateReleaseCandidateRejectsWrongTenantReferenceBeforeTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	fixture.references.err = ErrNotFound

	_, err := fixture.service.CreateReleaseCandidate(context.Background(), fixture.actor, CreateReleaseCandidateInput{
		ReleaseID: release.ID, Name: "candidate", SBOMIDs: []string{"sbom_other"},
	})
	if !errors.Is(err, ErrNotFound) || fixture.transactions.calls != 0 || fixture.canonicalizer.calls != 0 {
		t.Fatalf("error=%v transactions=%d canonicalizer=%d", err, fixture.transactions.calls, fixture.canonicalizer.calls)
	}
}

func TestCreateReleaseCandidateRequiresArtifactAuthorizationBeforeCanonicalizationOrTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: testSHA256('a')}
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: artifact.ID}) {
			return errDenied
		}
		return nil
	}

	_, err := fixture.service.CreateReleaseCandidate(context.Background(), fixture.actor, CreateReleaseCandidateInput{
		ReleaseID: release.ID, Name: "candidate", ArtifactIDs: []string{artifact.ID},
	})
	if !errors.Is(err, errDenied) {
		t.Fatalf("CreateReleaseCandidate error = %v, want denied", err)
	}
	if fixture.canonicalizer.calls != 0 || fixture.transactions.calls != 0 {
		t.Fatalf("denied command canonicalized=%d transactions=%d", fixture.canonicalizer.calls, fixture.transactions.calls)
	}
}

func TestUpdateReleaseCandidateStateReportsTransactionalVersionConflict(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	readCandidate := releasedomain.ReleaseCandidate{ID: "rc_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID, Revision: 1, State: state, SnapshotHash: testSHA256('d')}
	currentCandidate := readCandidate
	currentCandidate.Revision = 2
	fixture.reader.candidates[readCandidate.ID] = readCandidate
	fixture.transactions.state.candidates[currentCandidate.ID] = currentCandidate

	_, err := fixture.service.UpdateReleaseCandidateState(context.Background(), fixture.actor, readCandidate.ID, releasedomain.ReleaseCandidateStatePromotedValue, "approved", 1)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateReleaseCandidateState error = %v", err)
	}
	if revision, ok := CurrentRevision(err); !ok || revision != 2 {
		t.Fatalf("CurrentRevision = %d, %t", revision, ok)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || fixture.transactions.state.candidates[readCandidate.ID].Revision != 2 {
		t.Fatalf("transactions = %#v candidate=%#v", fixture.transactions, fixture.transactions.state.candidates[readCandidate.ID])
	}
}

func TestUpdateReleaseCandidateStateRejectsScopeDriftAndRollsBackAuditFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*serviceFixture, releasedomain.ReleaseCandidate)
		wantErr   error
	}{
		{
			name: "transaction wrong tenant",
			configure: func(fixture *serviceFixture, candidate releasedomain.ReleaseCandidate) {
				candidate.TenantID = "ten_other"
				fixture.transactions.state.candidates[candidate.ID] = candidate
			},
			wantErr: ErrNotFound,
		},
		{
			name: "scope drift",
			configure: func(fixture *serviceFixture, candidate releasedomain.ReleaseCandidate) {
				candidate.ReleaseID = "rel_other"
				fixture.transactions.state.candidates[candidate.ID] = candidate
			},
			wantErr: ErrConflict,
		},
		{name: "audit failure", configure: func(fixture *serviceFixture, _ releasedomain.ReleaseCandidate) {
			fixture.transactions.auditErr = errAudit
		}, wantErr: errAudit},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			_, _, release := seedReleaseScope(t, fixture)
			state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
			candidate := releasedomain.ReleaseCandidate{ID: "rc_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID, Revision: 1, State: state, SnapshotHash: testSHA256('d')}
			fixture.reader.candidates[candidate.ID] = candidate
			fixture.transactions.state.candidates[candidate.ID] = candidate
			test.configure(fixture, candidate)

			_, err := fixture.service.UpdateReleaseCandidateState(context.Background(), fixture.actor, candidate.ID, releasedomain.ReleaseCandidateStateRejectedValue, "not accepted", candidate.Revision)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("UpdateReleaseCandidateState error = %v, want %v", err, test.wantErr)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
				t.Fatalf("transactions = %#v", fixture.transactions)
			}
			if test.name == "audit failure" {
				stored := fixture.transactions.state.candidates[candidate.ID]
				if stored.Revision != 1 || stored.State.String() != releasedomain.ReleaseCandidateStateOpenValue || stored.RejectedAt != nil {
					t.Fatalf("candidate changed after rollback: %#v", stored)
				}
			}
		})
	}
}

func TestUpdateReleaseCandidateStateUsesOneTimestampForStateAndAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	candidate := releasedomain.ReleaseCandidate{ID: "rc_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID, Revision: 1, State: state, SnapshotHash: testSHA256('d')}
	fixture.reader.candidates[candidate.ID] = candidate
	fixture.transactions.state.candidates[candidate.ID] = candidate
	clockCalls := 0
	fixture.service.clock = application.ClockFunc(func() time.Time {
		at := fixture.now.Add(time.Duration(clockCalls) * time.Minute)
		clockCalls++
		return at
	})

	updated, err := fixture.service.UpdateReleaseCandidateState(context.Background(), fixture.actor, candidate.ID, releasedomain.ReleaseCandidateStatePromotedValue, "accepted", 1)
	if err != nil {
		t.Fatalf("UpdateReleaseCandidateState: %v", err)
	}
	if clockCalls != 1 || updated.Revision != 2 || updated.State.String() != releasedomain.ReleaseCandidateStatePromotedValue || updated.PromotedAt == nil {
		t.Fatalf("candidate=%#v clock=%d", updated, clockCalls)
	}
	if !updated.PromotedAt.Equal(fixture.transactions.state.audit[0].OccurredAt) {
		t.Fatalf("candidate=%#v audit=%#v", updated, fixture.transactions.state.audit)
	}
}

func TestReleaseCandidateQueriesAuthorizeStableReleaseCoordinates(t *testing.T) {
	fixture := newServiceFixture(t)
	product, _, release := seedReleaseScope(t, fixture)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	first := releasedomain.ReleaseCandidate{ID: "rc_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID, State: state, CreatedAt: fixture.now}
	secondRelease := release
	secondRelease.ID = "rel_2"
	fixture.reader.releases[secondRelease.ID] = secondRelease
	second := releasedomain.ReleaseCandidate{ID: "rc_2", TenantID: fixture.actor.TenantID, ReleaseID: secondRelease.ID, State: state, CreatedAt: fixture.now.Add(time.Minute)}
	fixture.reader.candidates[first.ID] = first
	fixture.reader.candidates[second.ID] = second

	got, err := fixture.service.GetReleaseCandidate(context.Background(), fixture.actor, first.ID)
	if err != nil || got.ID != first.ID {
		t.Fatalf("GetReleaseCandidate = (%#v, %v)", got, err)
	}
	want := application.ResourceReferences{ProductID: product.ID, ReleaseID: release.ID}
	if fixture.authorizer.requests[1].Resources != want {
		t.Fatalf("get authorization = %#v", fixture.authorizer.requests)
	}

	fixture.authorizer.requests = nil
	fixture.authorizer.calls = 0
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ReleaseID == secondRelease.ID {
			return ErrForbidden
		}
		return nil
	}
	listed, err := fixture.service.ListReleaseCandidates(context.Background(), fixture.actor, "")
	if err != nil || len(listed) != 1 || listed[0].ID != first.ID {
		t.Fatalf("ListReleaseCandidates = (%#v, %v)", listed, err)
	}
}

func TestListReleaseCandidatesPropagatesReleaseLookupFailure(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _, release := seedReleaseScope(t, fixture)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	fixture.reader.candidates["rc_1"] = releasedomain.ReleaseCandidate{
		ID: "rc_1", TenantID: fixture.actor.TenantID, ReleaseID: release.ID, State: state, CreatedAt: fixture.now,
	}
	wantErr := errors.New("release reader unavailable")
	fixture.service.reader = readerOverride{
		Reader: fixture.reader,
		getRelease: func(context.Context, string, string) (releasedomain.Release, error) {
			return releasedomain.Release{}, wantErr
		},
	}

	if _, err := fixture.service.ListReleaseCandidates(context.Background(), fixture.actor, ""); !errors.Is(err, wantErr) {
		t.Fatalf("ListReleaseCandidates error = %v, want %v", err, wantErr)
	}
}

func TestRegisterContainerImageIsIdempotentAfterArtifactValidation(t *testing.T) {
	fixture := newServiceFixture(t)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: digest}
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	existing := releasedomain.ContainerImage{ID: "img_existing", TenantID: fixture.actor.TenantID, ArtifactID: artifact.ID, Repository: "registry.example.test/api", Tag: "old", Digest: digest, SchemaVersion: releasedomain.ContainerImageSchemaVersion, CreatedAt: fixture.now.Add(-time.Hour)}
	fixture.transactions.state.images[existing.ID] = existing

	image, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
		ArtifactID: artifact.ID, Repository: " registry.example.test/api ", Tag: "new", Digest: " " + digest + " ", Platform: " linux/amd64 ",
	})
	if err != nil || !reflect.DeepEqual(image, existing) {
		t.Fatalf("RegisterContainerImage = (%#v, %v), want existing %#v", image, err, existing)
	}
	if fixture.transactions.calls != 1 || fixture.transactions.commits != 1 || len(fixture.transactions.state.images) != 1 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("transactions=%#v images=%#v audit=%#v", fixture.transactions, fixture.transactions.state.images, fixture.transactions.state.audit)
	}

	fixture = newServiceFixture(t)
	fixture.reader.artifacts[artifact.ID] = releasedomain.Artifact{ID: artifact.ID, TenantID: "ten_other", Digest: digest}
	if _, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api", Digest: digest}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-tenant RegisterContainerImage error = %v", err)
	}
	if fixture.transactions.calls != 0 {
		t.Fatalf("wrong-tenant transaction calls = %d", fixture.transactions.calls)
	}
}

func TestRegisterContainerImageExistingArtifactAssociationMustMatchAndBeAuthorized(t *testing.T) {
	digest := testSHA256('a')
	requestedArtifact := releasedomain.Artifact{ID: "art_requested", TenantID: "ten_1", Digest: digest}
	existingArtifact := releasedomain.Artifact{ID: "art_existing", TenantID: "ten_1", Digest: digest}
	existingImage := releasedomain.ContainerImage{
		ID: "img_existing", TenantID: "ten_1", ArtifactID: existingArtifact.ID,
		Repository: "registry.example.test/api", Tag: "old", Digest: digest,
		SchemaVersion: releasedomain.ContainerImageSchemaVersion,
	}

	newFixture := func(t *testing.T) *serviceFixture {
		t.Helper()
		fixture := newServiceFixture(t)
		fixture.reader.artifacts[requestedArtifact.ID] = requestedArtifact
		fixture.transactions.state.artifacts[requestedArtifact.ID] = requestedArtifact
		fixture.transactions.state.artifacts[existingArtifact.ID] = existingArtifact
		fixture.transactions.state.images[existingImage.ID] = existingImage
		return fixture
	}

	t.Run("different unauthorized artifact", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
			if request.Resources == (application.ResourceReferences{ArtifactID: existingArtifact.ID}) {
				return errDenied
			}
			return nil
		}

		image, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
			ArtifactID: requestedArtifact.ID, Repository: existingImage.Repository, Digest: digest,
		})
		if !errors.Is(err, errDenied) {
			t.Fatalf("RegisterContainerImage error = %v, want denied", err)
		}
		if image != (releasedomain.ContainerImage{}) {
			t.Fatalf("RegisterContainerImage leaked existing image = %#v", image)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})

	t.Run("different authorized artifact conflicts", func(t *testing.T) {
		fixture := newFixture(t)
		image, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
			ArtifactID: requestedArtifact.ID, Repository: existingImage.Repository, Digest: digest,
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("RegisterContainerImage error = %v, want conflict", err)
		}
		if image != (releasedomain.ContainerImage{}) {
			t.Fatalf("RegisterContainerImage returned mismatched existing image = %#v", image)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})

	t.Run("omitted artifact still authorizes existing association", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
			if request.Resources == (application.ResourceReferences{ArtifactID: existingArtifact.ID}) {
				return errDenied
			}
			return nil
		}
		if _, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
			Repository: existingImage.Repository, Digest: digest,
		}); !errors.Is(err, errDenied) {
			t.Fatalf("RegisterContainerImage error = %v, want denied", err)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})

	t.Run("omitted artifact returns authorized existing association", func(t *testing.T) {
		fixture := newFixture(t)
		image, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
			Repository: existingImage.Repository, Digest: digest,
		})
		if err != nil || !reflect.DeepEqual(image, existingImage) {
			t.Fatalf("RegisterContainerImage = (%#v, %v), want existing %#v", image, err, existingImage)
		}
		last := fixture.authorizer.requests[len(fixture.authorizer.requests)-1]
		if last.Scope != ScopeEvidenceWrite || last.ScopeOnly || last.Resources != (application.ResourceReferences{ArtifactID: existingArtifact.ID}) {
			t.Fatalf("existing association authorization = %#v", fixture.authorizer.requests)
		}
	})

	t.Run("cannot attach artifact to existing unassociated image", func(t *testing.T) {
		fixture := newFixture(t)
		unassociated := existingImage
		unassociated.ArtifactID = ""
		fixture.transactions.state.images[existingImage.ID] = unassociated
		if _, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{
			ArtifactID: requestedArtifact.ID, Repository: existingImage.Repository, Digest: digest,
		}); !errors.Is(err, ErrConflict) {
			t.Fatalf("RegisterContainerImage error = %v, want conflict", err)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})
}

func TestRegisterContainerImageRollsBackScopeDriftAndAuditFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*serviceFixture, releasedomain.Artifact)
		wantErr   error
	}{
		{
			name: "artifact digest drift",
			configure: func(fixture *serviceFixture, artifact releasedomain.Artifact) {
				artifact.Digest = testSHA256('b')
				fixture.transactions.state.artifacts[artifact.ID] = artifact
			},
			wantErr: ErrConflict,
		},
		{name: "audit failure", configure: func(fixture *serviceFixture, _ releasedomain.Artifact) { fixture.transactions.auditErr = errAudit }, wantErr: errAudit},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			digest := testSHA256('a')
			artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Digest: digest}
			fixture.reader.artifacts[artifact.ID] = artifact
			fixture.transactions.state.artifacts[artifact.ID] = artifact
			test.configure(fixture, artifact)

			_, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api", Digest: digest})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("RegisterContainerImage error = %v, want %v", err, test.wantErr)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.images) != 0 {
				t.Fatalf("transactions=%#v images=%#v", fixture.transactions, fixture.transactions.state.images)
			}
		})
	}
}

func TestRegisterContainerImageUsesOneTimestampForRecordAndAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	clockCalls := 0
	fixture.service.clock = application.ClockFunc(func() time.Time {
		at := fixture.now.Add(time.Duration(clockCalls) * time.Minute)
		clockCalls++
		return at
	})
	digest := testSHA256('a')

	image, err := fixture.service.RegisterContainerImage(context.Background(), fixture.actor, RegisterContainerImageInput{Repository: "registry.example.test/api", Digest: digest})
	if err != nil {
		t.Fatalf("RegisterContainerImage: %v", err)
	}
	if clockCalls != 1 || !image.CreatedAt.Equal(fixture.transactions.state.audit[0].OccurredAt) {
		t.Fatalf("image=%#v audit=%#v clock=%d", image, fixture.transactions.state.audit, clockCalls)
	}
}

func seedReleaseScope(t *testing.T, fixture *serviceFixture) (releasedomain.Product, releasedomain.Project, releasedomain.Release) {
	t.Helper()
	state, err := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	if err != nil {
		t.Fatal(err)
	}
	product := releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID}
	project := releasedomain.Project{ID: "proj_1", TenantID: fixture.actor.TenantID, ProductID: product.ID}
	release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: product.ID, Revision: 1, State: state}
	fixture.reader.products[product.ID] = product
	fixture.reader.projects[project.ID] = project
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.products[product.ID] = product
	fixture.transactions.state.projects[project.ID] = project
	fixture.transactions.state.releases[release.ID] = release
	return product, project, release
}

func testSHA256(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
