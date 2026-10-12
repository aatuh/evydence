package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type catalogCreationFixtureResult struct {
	product releasedomain.Product
	project releasedomain.Project
	release releasedomain.Release
}

func TestCatalogCreationNativeFixturesUseCurrentRowsWithoutAggregateClockAndCommitAtomically(t *testing.T) {
	for _, action := range []string{"product", "project", "release"} {
		t.Run(action, func(t *testing.T) {
			ledger, base := integrationRegressionLedger()
			owner := seedEvidenceFixtureParents(t, ledger, "Owner")
			foreign := seedEvidenceFixtureParents(t, ledger, "Foreign")
			factory := &bundleWriteFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("catalog creation used aggregate clock") }})
			f := catalogFixtureCommands{ledger: rebound}
			guard := func(ctx context.Context, actor domain.Actor, label string) error {
				switch action {
				case "product":
					return f.AuthorizeProductCreation(ctx, actor, releaseapp.CreateProductInput{Name: label, Slug: label})
				case "project":
					return f.AuthorizeProjectCreation(ctx, actor, releaseapp.CreateProjectInput{ProductID: owner.product.ID, Name: label})
				default:
					return f.AuthorizeReleaseCreation(ctx, actor, releaseapp.CreateReleaseInput{ProductID: owner.product.ID, Version: label})
				}
			}
			run := func(ctx context.Context, label string) (catalogCreationFixtureResult, error) {
				var v catalogCreationFixtureResult
				var err error
				switch action {
				case "product":
					v.product, err = f.CreateProduct(ctx, owner.actor, releaseapp.CreateProductInput{Name: label, Slug: label})
				case "project":
					v.project, err = f.CreateProject(ctx, owner.actor, releaseapp.CreateProjectInput{ProductID: owner.product.ID, Name: label})
				default:
					v.release, err = f.CreateRelease(ctx, owner.actor, releaseapp.CreateReleaseInput{ProductID: owner.product.ID, Version: label})
				}
				return v, err
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := guard(t.Context(), owner.actor, "created"); err != nil {
				t.Fatal("current catalog ownership rejected", err)
			}
			if action != "product" {
				if err := guard(t.Context(), foreign.actor, "created"); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("catalog parent crossed tenant boundary", err)
				}
			}
			human := owner.actor
			human.KeyID, human.UserID = "", "human"
			if err := guard(t.Context(), human, "created"); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("catalog guard retained absent grants", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if v, err := run(ctx, "cancelled"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, catalogCreationFixtureResult{}) {
				t.Fatal("cancelled catalog write returned data", err)
			}
			guarded, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, guarded) {
				t.Fatal("catalog guard/cancellation wrote effects", err)
			}
			started := factory.begins
			v, err := run(t.Context(), "created")
			if err != nil {
				t.Fatal("focused catalog write failed", err)
			}
			steps := factory.begins - started
			after, err := base.Snapshot()
			if err != nil || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(after.OutboxJobs, before.OutboxJobs) {
				t.Fatal("catalog row/audit did not commit together", err)
			}
			switch action {
			case "product":
				if v.product.ID == "" || len(after.Products) != len(before.Products)+1 || after.Products[v.product.ID].TenantID != owner.actor.TenantID || after.Products[v.product.ID].Name != "created" {
					t.Fatal("product fields lost at commit")
				}
				if v, err := run(t.Context(), "created"); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, catalogCreationFixtureResult{}) {
					t.Fatal("duplicate product slug accepted", err)
				}
			case "project":
				if v.project.ID == "" || len(after.Projects) != len(before.Projects)+1 || after.Projects[v.project.ID].ProductID != owner.product.ID || after.Projects[v.project.ID].Name != "created" {
					t.Fatal("project fields lost at commit")
				}
			case "release":
				if v.release.ID == "" || v.release.State.String() != "draft" || v.release.Revision != 1 || len(after.Releases) != len(before.Releases)+1 || after.Releases[v.release.ID].ProductID != owner.product.ID || after.Releases[v.release.ID].Version != "created" {
					t.Fatal("release fields lost at commit")
				}
				if v, err := run(t.Context(), "created"); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, catalogCreationFixtureResult{}) {
					t.Fatal("duplicate release version accepted", err)
				}
			}
			factory.failAt = factory.begins + steps
			if v, err := run(t.Context(), "commit-failure"); err == nil || !reflect.DeepEqual(v, catalogCreationFixtureResult{}) || factory.begins != factory.failAt {
				t.Fatal("real catalog write commit failure not reached or exposed data", err)
			}
			failed, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, failed) {
				t.Fatal("failed catalog commit published effects", err)
			}
		})
	}
}
