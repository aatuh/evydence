package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestBuildCreationBoundsRawInputBeforeWrites(t *testing.T) {
	for _, mutate := range []func(*CreateBuildRunInput){func(in *CreateBuildRunInput) { in.ProjectID = strings.Repeat(" ", 1025) + in.ProjectID }, func(in *CreateBuildRunInput) { in.ReleaseID = strings.Repeat(" ", 1025) + in.ReleaseID }, func(in *CreateBuildRunInput) { in.Repository = strings.Repeat(" ", 65537) + "repository" }, func(in *CreateBuildRunInput) {
		in.Outputs = []releasedomain.BuildOutput{{ArtifactID: strings.Repeat(" ", 1025) + "artifact", Digest: testSHA256('a')}}
	}, func(in *CreateBuildRunInput) {
		in.ProviderMetadata = map[string]any{"blob": strings.Repeat("x", 65537)}
	}, func(in *CreateBuildRunInput) {
		in.RunAttempt = -1
	}, func(in *CreateBuildRunInput) {
		in.StartedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 14*3600))
	}, func(in *CreateBuildRunInput) {
		end := time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("offset", -12*3600))
		in.FinishedAt = &end
	}} {
		f := newServiceFixture(t)
		_, project, release := seedReleaseScope(t, f)
		in := CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now}
		mutate(&in)
		if v, err := f.service.CreateBuildRun(t.Context(), f.actor, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions.calls != 0 {
			t.Fatal("raw build input escaped bounds", v, err, f.transactions.calls)
		}
	}
}

func TestBuildCommandsExposeReadOnlyCurrentCreationGuard(t *testing.T) {
	f := newServiceFixture(t)
	commands, err := NewBuildCommands(BuildCommandConfig{Reader: f.reader, Authorizer: f.authorizer, Transactions: releaseBuildTransactions{runner: f.transactions}, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(commands).(interface {
		AuthorizeBuildCreation(context.Context, identitydomain.Actor, CreateBuildRunInput) error
	}); !ok {
		t.Fatal("build commands lack read-only current creation guard")
	}
}
