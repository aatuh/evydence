package app

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestBuildCollectorAttributionRejectsUnboundOrConflictingMetadataBeforeEffectsAndReplay(t *testing.T) {
	for _, tc := range []struct {
		name, bound string
		claim       any
	}{
		{"different collector", "collector", "other"},
		{"unbound collector", "", "collector"},
		{"padded collector", "collector", " collector "},
		{"nonstring collector", "collector", 42},
		{"null collector", "collector", nil},
		{"empty collector", "collector", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServiceFixture(t)
			product, project, release := seedReleaseScope(t, f)
			f.actor.CollectorID = tc.bound
			in := CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now, ProviderMetadata: map[string]any{"collector_id": tc.claim, "job": "job"}}
			config := BuildCommandConfig{Reader: f.reader, Authorizer: f.authorizer, Transactions: releaseBuildTransactions{runner: f.transactions}, Clock: f.service.clock, IDs: f.service.ids}
			c, err := NewBuildCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateBuildRun(t.Context(), f.actor, in)
			if !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(v, releasedomain.BuildRun{}) || f.transactions.calls != 0 || len(f.transactions.state.builds) != 0 || len(f.transactions.state.audit) != 0 {
				t.Errorf("forged attribution reached build effects: err=%v", err)
			}
			guard := &buildGuardFake{parents: BuildCreationCoordinates{TenantID: f.actor.TenantID, ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, ReleaseProductID: product.ID}}
			config.Transactions = guard
			c, err = NewBuildCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeBuildCreation(t.Context(), f.actor, in); !errors.Is(err, application.ErrForbidden) || guard.scopeReads != 0 || guard.authorizations != 0 {
				t.Errorf("forged attribution reached build replay ownership lookups: err=%v", err)
			}
		})
	}
}

func TestBuildCollectorAttributionPreservesMatchingMetadataAndAuthenticatedAudit(t *testing.T) {
	f := newServiceFixture(t)
	_, project, release := seedReleaseScope(t, f)
	f.actor.CollectorID = "collector"
	in := CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now, ProviderMetadata: map[string]any{"collector_id": "collector", "job": "job"}}
	before := cloneAnyMap(in.ProviderMetadata)
	v, err := f.service.CreateBuildRun(t.Context(), f.actor, in)
	if err != nil || v.CollectorID != "collector" || v.SourceIdentity["collector_id"] != "collector" || v.SourceIdentity["job"] != "job" || !reflect.DeepEqual(in.ProviderMetadata, before) || f.transactions.commits != 1 || len(f.transactions.state.audit) != 1 {
		t.Fatal("matching attribution lost identity, metadata or atomic effects", err)
	}
	audit := f.transactions.state.audit[0]
	if audit.ActorType != "collector" || audit.ActorID != "collector" || audit.SubjectID != v.ID {
		t.Fatal("build audit attribution differs from authenticated collector")
	}
}
