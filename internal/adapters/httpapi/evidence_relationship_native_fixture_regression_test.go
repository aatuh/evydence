package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type relationshipFixtureResult struct {
	evidence  evidencedomain.EvidenceItem
	lifecycle evidencedomain.EvidenceLifecycleEvent
}

func TestEvidenceRelationshipNativeFixturesUseCurrentScopeWithoutAggregateClockAndCommitAtomically(t *testing.T) {
	for _, action := range []string{"supersede", "link", "lifecycle"} {
		t.Run(action, func(t *testing.T) {
			ledger, base := integrationRegressionLedger()
			owner := seedEvidenceFixtureScope(t, ledger, "Owner")
			foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
			release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
			if err != nil {
				t.Fatal(err)
			}
			secondOriginal, err := createEvidenceFixture(t.Context(), ledger, owner.actor, app.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Title: "Second original", PayloadHash: owner.original.PayloadHash})
			if err != nil {
				t.Fatal(err)
			}
			secondReplacement, err := createEvidenceFixture(t.Context(), ledger, owner.actor, app.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Title: "Second replacement", PayloadHash: owner.replacement.PayloadHash})
			if err != nil {
				t.Fatal(err)
			}
			factory := &bundleWriteFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("relationship used aggregate clock") }})
			f := evidenceFixtureCommands{catalogFixtureCommands{ledger: rebound}}
			input := evidenceapp.RecordLifecycleInput{Action: "amendment", Reason: "reviewed", Details: map[string]any{"sequence": json.Number("9007199254740993"), "secret": "private-value"}}
			guard := func(ctx context.Context, a domain.Actor, original, replacement string) error {
				switch action {
				case "supersede":
					return f.AuthorizeSupersedeEvidence(ctx, a, original, replacement, "reviewed")
				case "link":
					return f.AuthorizeLinkEvidence(ctx, a, original, "release", release.ID)
				default:
					in := input
					in.ReplacementID = replacement
					return f.AuthorizeLifecycleEvent(ctx, a, original, in)
				}
			}
			run := func(ctx context.Context, original, replacement string) (relationshipFixtureResult, error) {
				var result relationshipFixtureResult
				var err error
				switch action {
				case "supersede":
					result.evidence, err = f.SupersedeEvidence(ctx, owner.actor, original, replacement, "reviewed")
				case "link":
					result.evidence, err = f.LinkEvidence(ctx, owner.actor, original, "release", release.ID)
				default:
					in := input
					in.ReplacementID = replacement
					result.lifecycle, err = f.RecordLifecycleEvent(ctx, owner.actor, original, in)
				}
				return result, err
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := guard(t.Context(), owner.actor, owner.original.ID, owner.replacement.ID); err != nil {
				t.Fatal("cold aggregate guard rejected current rows", err)
			}
			if err := guard(t.Context(), foreign.actor, owner.original.ID, owner.replacement.ID); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("guard crossed tenant boundary", err)
			}
			human := owner.actor
			human.KeyID, human.UserID = "", "human"
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}
			if err := guard(t.Context(), human, owner.original.ID, owner.replacement.ID); err != nil {
				t.Fatal("guard rejected current product grant", err)
			}
			human.ResourceGrants = nil
			if err := guard(t.Context(), human, owner.original.ID, owner.replacement.ID); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("guard retained removed product grant", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if v, err := run(ctx, owner.original.ID, owner.replacement.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, relationshipFixtureResult{}) {
				t.Fatal("cancelled relationship returned data", err)
			}
			guarded, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, guarded) {
				t.Fatal("relationship preflight/cancellation wrote effects", err)
			}
			started := factory.begins
			v, err := run(t.Context(), owner.original.ID, owner.replacement.ID)
			if err != nil {
				t.Fatal("focused relationship failed", err)
			}
			steps := factory.begins - started
			after, err := base.Snapshot()
			if err != nil || len(after.Evidence) != len(before.Evidence) || len(after.EvidenceLifecycle) != len(before.EvidenceLifecycle)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(before.OutboxJobs, after.OutboxJobs) || after.Evidence[owner.original.ID].CanonicalHash != owner.original.CanonicalHash || after.Evidence[owner.replacement.ID].CanonicalHash != owner.replacement.CanonicalHash {
				t.Fatal("relationship/effect cardinality or immutable hashes changed", err)
			}
			switch action {
			case "supersede":
				if v.evidence.SupersededBy != owner.replacement.ID || after.Evidence[owner.replacement.ID].Supersedes != owner.original.ID {
					t.Fatal("supersession did not bind both owned rows")
				}
			case "link":
				if v.evidence.ReleaseID != release.ID || after.Evidence[owner.original.ID].ReleaseID != release.ID {
					t.Fatal("link did not commit current release")
				}
			case "lifecycle":
				stored := after.EvidenceLifecycle[v.lifecycle.ID]
				if v.lifecycle.Details["sequence"] != json.Number("9007199254740993") || stored.Details["sequence"] != json.Number("9007199254740993") || v.lifecycle.Details["secret"] != nil || stored.Details["secret"] != nil {
					t.Fatal("lifecycle details rounded or leaked sensitive fields")
				}
			}
			factory.failAt = factory.begins + steps
			if v, err := run(t.Context(), secondOriginal.ID, secondReplacement.ID); err == nil || !reflect.DeepEqual(v, relationshipFixtureResult{}) || factory.begins != factory.failAt {
				t.Fatal("real relationship write commit failure was not exercised or returned data", err)
			}
			failed, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, failed) {
				t.Fatal("failed relationship commit published effects", err)
			}
		})
	}
}
