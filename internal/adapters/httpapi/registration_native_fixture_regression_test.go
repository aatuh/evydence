package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type registrationFixtureResult struct {
	artifact releasedomain.Artifact
	image    releasedomain.ContainerImage
}

func TestRegistrationNativeFixturesUseCurrentRowsAndImmutableIdentityWithoutAggregateClock(t *testing.T) {
	for _, action := range []string{"artifact", "image"} {
		t.Run(action, func(t *testing.T) {
			ledger, base := integrationRegressionLedger()
			owner := seedEvidenceFixtureParents(t, ledger, "Owner")
			foreign := seedEvidenceFixtureParents(t, ledger, "Foreign")
			seed := registrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
			digest := "sha256:" + strings.Repeat("a", 64)
			artifact, err := seed.RegisterArtifact(t.Context(), owner.actor, releaseapp.RegisterArtifactInput{Name: "original", MediaType: "application/octet-stream", Digest: digest, Size: 9007199254740993})
			if err != nil {
				t.Fatal(err)
			}
			project, err := seed.CreateProject(t.Context(), owner.actor, releaseapp.CreateProjectInput{ProductID: owner.product.ID, Name: "Project"})
			if err != nil {
				t.Fatal(err)
			}
			release, err := seed.CreateRelease(t.Context(), owner.actor, releaseapp.CreateReleaseInput{ProductID: owner.product.ID, Version: "1"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.CreateBuildRun(t.Context(), owner.actor, releaseapp.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("b", 40), Status: "passed", StartedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Outputs: []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: digest}}}); err != nil {
				t.Fatal(err)
			}
			if action == "image" {
				if _, err := seed.RegisterContainerImage(t.Context(), owner.actor, releaseapp.RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.test/product", Digest: digest}); err != nil {
					t.Fatal(err)
				}
			}
			factory := &bundleWriteFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("registration used aggregate clock") }})
			f := registrationFixtureCommands{catalogFixtureCommands{ledger: rebound}}
			guard := func(ctx context.Context, a domain.Actor) error {
				if action == "artifact" {
					return f.AuthorizeArtifactRegistration(ctx, a, releaseapp.RegisterArtifactInput{Name: "changed", MediaType: "changed", Digest: digest, Size: 1})
				}
				return f.AuthorizeContainerImageRegistration(ctx, a, releaseapp.RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.test/product", Digest: digest})
			}
			run := func(ctx context.Context, value string) (registrationFixtureResult, error) {
				var v registrationFixtureResult
				var err error
				if action == "artifact" {
					v.artifact, err = f.RegisterArtifact(ctx, owner.actor, releaseapp.RegisterArtifactInput{Name: value, MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat(value, 64), Size: 9007199254740993})
				} else {
					v.image, err = f.RegisterContainerImage(ctx, owner.actor, releaseapp.RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.test/" + value, Tag: "original", Digest: digest, Platform: "linux/amd64"})
				}
				return v, err
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := guard(t.Context(), owner.actor); err != nil {
				t.Fatal("cold registration guard rejected current rows", err)
			}
			if action == "image" {
				if err := guard(t.Context(), foreign.actor); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("image guard accepted foreign artifact", err)
				}
			}
			human := owner.actor
			human.KeyID, human.UserID = "", "human"
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{app.ScopeEvidenceWrite}}}
			if err := guard(t.Context(), human); err != nil {
				t.Fatal("current build association did not grant artifact reuse", err)
			}
			if action == "image" {
				if err := f.AuthorizeContainerImageRegistration(t.Context(), human, releaseapp.RegisterContainerImageInput{Repository: "registry.test/product", Digest: digest}); err != nil {
					t.Fatal("owned existing image attachment was not authorized", err)
				}
			}
			human.ResourceGrants = nil
			if err := guard(t.Context(), human); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("registration guard retained absent artifact grants", err)
			}
			if action == "image" {
				if err := f.AuthorizeContainerImageRegistration(t.Context(), human, releaseapp.RegisterContainerImageInput{Repository: "registry.test/product", Digest: digest}); !errors.Is(err, app.ErrForbidden) {
					t.Fatal("omitting submitted artifact bypassed existing attachment grant", err)
				}
				if v, err := f.RegisterContainerImage(t.Context(), human, releaseapp.RegisterContainerImageInput{Repository: "registry.test/product", Digest: digest}); !errors.Is(err, app.ErrForbidden) || v != (releasedomain.ContainerImage{}) {
					t.Fatal("denied image duplicate returned immutable metadata", err)
				}
			} else {
				if v, err := f.RegisterArtifact(t.Context(), human, releaseapp.RegisterArtifactInput{Name: "denied", MediaType: "changed", Digest: digest}); !errors.Is(err, app.ErrForbidden) || v != (releasedomain.Artifact{}) {
					t.Fatal("denied artifact duplicate returned private metadata", err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if v, err := run(ctx, "b"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, registrationFixtureResult{}) {
				t.Fatal("cancelled registration exposed data", err)
			}
			guarded, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, guarded) {
				t.Fatal("registration preflight/cancellation changed state", err)
			}
			started := factory.begins
			v, err := run(t.Context(), "b")
			if err != nil {
				t.Fatal("focused registration failed", err)
			}
			steps := factory.begins - started
			after, err := base.Snapshot()
			if err != nil || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
				t.Fatal("registration row and audit did not commit together", err)
			}
			if action == "artifact" {
				if v.artifact.ID == "" || after.Artifacts[v.artifact.ID].Size != 9007199254740993 || len(after.Artifacts) != len(before.Artifacts)+1 {
					t.Fatal("artifact lost exact immutable metadata")
				}
				duplicate, err := f.RegisterArtifact(t.Context(), owner.actor, releaseapp.RegisterArtifactInput{Name: "replacement", MediaType: "changed", Digest: digest, Size: 1})
				if err != nil || !reflect.DeepEqual(duplicate, artifact) {
					t.Fatal("artifact duplicate changed original record", duplicate, err)
				}
			} else {
				if v.image.ID == "" || after.ContainerImages[v.image.ID].ArtifactID != artifact.ID || len(after.ContainerImages) != len(before.ContainerImages)+1 {
					t.Fatal("image lost owned artifact binding")
				}
				duplicate, err := f.RegisterContainerImage(t.Context(), owner.actor, releaseapp.RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: v.image.Repository, Digest: digest, Tag: "replacement", Platform: "changed"})
				if err != nil || !reflect.DeepEqual(duplicate, v.image) {
					t.Fatal("image duplicate changed original record", duplicate, err)
				}
			}
			reused, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, reused) {
				t.Fatal("immutable duplicate wrote effects", err)
			}
			factory.failAt = factory.begins + steps
			if v, err := run(t.Context(), "c"); err == nil || !reflect.DeepEqual(v, registrationFixtureResult{}) || factory.begins != factory.failAt {
				t.Fatal("final registration write commit failure not reached or exposed result", err)
			}
			failed, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, failed) {
				t.Fatal("failed registration commit published effects", err)
			}
		})
	}
}
