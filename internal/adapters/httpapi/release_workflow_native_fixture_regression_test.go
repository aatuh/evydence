package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type releaseWorkflowFixtureResult struct {
	build       releasedomain.BuildRun
	candidate   releasedomain.ReleaseCandidate
	release     releasedomain.Release
	attestation releasedomain.BuildAttestation
}

func TestReleaseWorkflowNativeFixturesUseRepositoryOnlyParentsAndRollBackWriteCommit(t *testing.T) {
	for _, action := range []string{"build", "candidate", "release-state", "attestation"} {
		t.Run(action, func(t *testing.T) {
			ledger, base := integrationRegressionLedger()
			owner := seedEvidenceFixtureParents(t, ledger, "Owner")
			foreign := seedEvidenceFixtureParents(t, ledger, "Foreign")
			catalog := catalogFixtureCommands{ledger: ledger}
			product, err := catalog.CreateProduct(t.Context(), owner.actor, releaseapp.CreateProductInput{Name: "Current", Slug: "current"})
			if err != nil {
				t.Fatal(err)
			}
			project, err := catalog.CreateProject(t.Context(), owner.actor, releaseapp.CreateProjectInput{ProductID: product.ID, Name: "Current"})
			if err != nil {
				t.Fatal(err)
			}
			release, err := catalog.CreateRelease(t.Context(), owner.actor, releaseapp.CreateReleaseInput{ProductID: product.ID, Version: "current"})
			if err != nil {
				t.Fatal(err)
			}
			registration := registrationFixtureCommands{catalog}
			buildInput := releaseapp.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC), Outputs: []releasedomain.BuildOutput{{Digest: "sha256:" + strings.Repeat("a", 64)}}}
			build, err := registration.CreateBuildRun(t.Context(), owner.actor, buildInput)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "recorded-only", "sig": "c2ln"}}})
			if err != nil {
				t.Fatal(err)
			}
			factory := &bundleWriteFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("release workflow used aggregate clock") }})
			reg := registrationFixtureCommands{catalogFixtureCommands{ledger: rebound}}
			life := lifecycleFixtureCommands{catalogFixtureCommands{ledger: rebound}}
			guard := func(ctx context.Context, a domain.Actor) error {
				switch action {
				case "build":
					return reg.AuthorizeBuildCreation(ctx, a, buildInput)
				case "candidate":
					return reg.AuthorizeCandidateCreation(ctx, a, releaseapp.CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "current", BuildIDs: []string{build.ID}})
				case "release-state":
					return life.AuthorizeReleaseTransition(ctx, a, release.ID)
				default:
					return life.AuthorizeBuildAttestationCreation(ctx, a, build.ID)
				}
			}
			run := func(ctx context.Context, label string) (releaseWorkflowFixtureResult, error) {
				var v releaseWorkflowFixtureResult
				var err error
				switch action {
				case "build":
					in := buildInput
					in.RunID = label
					v.build, err = reg.CreateBuildRun(ctx, owner.actor, in)
				case "candidate":
					v.candidate, err = reg.CreateReleaseCandidate(ctx, owner.actor, releaseapp.CreateReleaseCandidateInput{ReleaseID: release.ID, Name: label, BuildIDs: []string{build.ID}})
				case "release-state":
					if label == "created" {
						v.release, err = life.FreezeRelease(ctx, owner.actor, release.ID, 1)
					} else {
						v.release, err = life.ApproveRelease(ctx, owner.actor, release.ID, 2)
					}
				default:
					v.attestation, err = life.UploadBuildAttestation(ctx, owner.actor, build.ID, raw)
				}
				return v, err
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := guard(t.Context(), owner.actor); err != nil {
				t.Fatal("cold-cache guard rejected current parents", err)
			}
			if err := guard(t.Context(), foreign.actor); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("workflow guard crossed tenant boundary", err)
			}
			human := owner.actor
			human.KeyID, human.UserID = "", "human"
			if err := guard(t.Context(), human); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("workflow retained absent grants", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if v, err := run(ctx, "cancelled"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, releaseWorkflowFixtureResult{}) {
				t.Fatal("cancelled workflow returned data", err)
			}
			guarded, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, guarded) {
				t.Fatal("workflow preflight/cancellation wrote effects", err)
			}
			started := factory.begins
			v, err := run(t.Context(), "created")
			if err != nil {
				t.Fatal("focused workflow failed", err)
			}
			steps := factory.begins - started
			after, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			wantAudit := 1
			if action == "attestation" {
				wantAudit = 2
			}
			if len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+wantAudit {
				t.Fatal("workflow audit did not commit with result")
			}
			switch action {
			case "build":
				if v.build.ID == "" || len(after.BuildRuns) != len(before.BuildRuns)+1 || after.BuildRuns[v.build.ID].ProjectID != project.ID {
					t.Fatal("build result lost current parent")
				}
			case "candidate":
				if v.candidate.ID == "" || v.candidate.SnapshotHash == "" || !reflect.DeepEqual(after.ReleaseCandidates[v.candidate.ID].BuildIDs, []string{build.ID}) {
					t.Fatal("candidate lost bound build or snapshot")
				}
			case "release-state":
				if v.release.Revision != 2 || after.Releases[release.ID].State != "frozen" {
					t.Fatal("release state/revision did not commit")
				}
			case "attestation":
				if v.attestation.ID == "" || v.attestation.EvidenceID == "" || v.attestation.VerificationStatus == "passed" || len(after.BuildAttestations) != len(before.BuildAttestations)+1 || after.Evidence[v.attestation.EvidenceID].BuildID != build.ID {
					t.Fatal("attestation/evidence did not commit or parsing assigned trust")
				}
			}
			factory.failAt = factory.begins + steps
			if v, err := run(t.Context(), "commit-failure"); err == nil || !reflect.DeepEqual(v, releaseWorkflowFixtureResult{}) || factory.begins != factory.failAt {
				t.Fatal("real workflow write commit failure not reached or exposed data", err)
			}
			failed, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, failed) {
				t.Fatal("failed workflow write commit published effects", err)
			}
		})
	}
}
