package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneBuildCommandsPreserveParentArtifactAndAuditBoundaries(t *testing.T) {
	fixture := newServiceFixture(t)
	_, project, release := seedReleaseScope(t, fixture)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "art_output", TenantID: fixture.actor.TenantID, Digest: digest}
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	fixture.actor.CollectorID = "col_1"
	commands, err := NewBuildCommands(BuildCommandConfig{
		Reader: fixture.reader, Authorizer: fixture.authorizer,
		Transactions: releaseBuildTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_standalone" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	input := CreateBuildRunInput{
		ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40),
		Status: "passed", StartedAt: fixture.now,
		Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}},
	}
	build, err := commands.CreateBuildRun(context.Background(), fixture.actor, input)
	if err != nil || build.ID != "build_standalone" || build.ProjectID != project.ID || build.ReleaseID != release.ID {
		t.Fatalf("create build=%#v err=%v", build, err)
	}
	if build.SourceIdentity["source"] != "collector" || build.SourceIdentity["oidc_verified"] != false ||
		len(fixture.transactions.state.builds) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("build identity or transaction state invalid: %#v %#v", build, fixture.transactions.state)
	}
	foreign := fixture.actor
	foreign.TenantID = "ten_foreign"
	before := fixture.transactions.calls
	if _, err := commands.CreateBuildRun(context.Background(), foreign, input); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign parent err=%v, want not found", err)
	}
	if fixture.transactions.calls != before {
		t.Fatal("foreign parent opened a transaction")
	}
	fixture.transactions.auditErr = errAudit
	commands.ids = application.IDGeneratorFunc(func(prefix string) string { return prefix + "_rollback" })
	if _, err := commands.CreateBuildRun(context.Background(), fixture.actor, input); !errors.Is(err, errAudit) {
		t.Fatalf("audit failure err=%v, want audit error", err)
	}
	if len(fixture.transactions.state.builds) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit failure committed a build: %#v", fixture.transactions.state)
	}
}

func TestBuildCreationReauthorizesParentsAndArtifactsBeforeAnyWrites(t *testing.T) {
	for _, deniedResource := range []string{"parent", "artifact"} {
		t.Run(deniedResource, func(t *testing.T) {
			fixture := newServiceFixture(t)
			_, project, release := seedReleaseScope(t, fixture)
			digest := testSHA256('a')
			artifact := releasedomain.Artifact{ID: "artifact", TenantID: fixture.actor.TenantID, Digest: digest}
			fixture.reader.artifacts[artifact.ID] = artifact
			fixture.transactions.state.artifacts[artifact.ID] = artifact
			fixture.transactions.beforeCommand = func(_ *fakeState) {
				fixture.authorizer.authorize = func(r application.AuthorizationRequest) error {
					if deniedResource == "parent" && r.Resources.ProjectID != "" || deniedResource == "artifact" && r.Resources.ArtifactID != "" {
						return application.ErrForbidden
					}
					return nil
				}
			}
			v, err := fixture.service.CreateBuildRun(t.Context(), fixture.actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: fixture.now, Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}}})
			if !errors.Is(err, application.ErrForbidden) || v.ID != "" || len(fixture.transactions.state.builds) != 0 || len(fixture.transactions.state.audit) != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
				t.Fatal("revoked authority committed build", v, err, fixture.transactions)
			}
		})
	}
}
